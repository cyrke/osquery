/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <functional>
#include <getopt.h>
#include <iostream>
#include <map>
#include <string.h>
#include <unistd.h>

#include <libudev.h>
#include <smartmontools/libsmartctl.h>
#include <smartmontools/smartctl_errs.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"

namespace osquery {
namespace tables {

struct explicitDevice {
  std::string driver;
  int maxID;
};

// delUdevDevice is a lambda function meant to be used with smart pointers for
// unreffing for udev_device pointers
auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };

// Look-up table for driver to smartctl controller name.
// static const std::map<std::string> kSWDriverToClter = {"ahci", "mpt3sas"};

static const std::map<std::string, explicitDevice> kExplicitDriverToDevice = {
    {"megaraid_sas", explicitDevice{"megaraid,", 127}},
    {"hpsa", explicitDevice{"cciss,", 14}},
};

void walkUdevSubSystem(
    std::string subsystem,
    std::function<void(udev_list_entry* const&, udev* const&)> handleDevF) {
  auto delUdev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(delUdev)> ud(udev_new(), delUdev);

  if (ud.get() == nullptr) {
    LOG(ERROR) << "Could not get libudev handle";
    return;
  }

  auto delUdevEnum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(delUdevEnum)> enumerate(
      udev_enumerate_new(ud.get()), delUdevEnum);

  udev_enumerate_add_match_subsystem(enumerate.get(), subsystem.c_str());
  udev_enumerate_scan_devices(enumerate.get());
  udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate.get());

  udev_list_entry* dev_list_entry;
  udev_list_entry_foreach(dev_list_entry, devices) {
    handleDevF(dev_list_entry, ud.get());
  }
}

std::vector<std::string> getBlkDevices() {
  std::vector<std::string> results;

  walkUdevSubSystem(
      "block", [&results](udev_list_entry* const& entry, udev* const& ud) {
        const char* path = udev_list_entry_get_name(entry);
        if (path == nullptr) {
          return;
        }
        if (strstr(path, "virtual")) {
          return;
        }

        std::unique_ptr<udev_device, decltype(delUdevDevice)> dev(
            udev_device_new_from_syspath(ud, path), delUdevDevice);
        if (dev.get() == nullptr) {
          return;
        }

        results.push_back(udev_device_get_devnode(dev.get()));
      });

  return results;
}

std::vector<std::string> getStorageCtlerClassDrivers() {
  std::vector<std::string> results;

  walkUdevSubSystem(
      "pci", [&results](udev_list_entry* const& entry, udev* const& ud) {
        const char* path = udev_list_entry_get_name(entry);
        if (path == nullptr) {
          return;
        }

        std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
            udev_device_new_from_syspath(ud, path), delUdevDevice);
        if (device.get() == nullptr) {
          return;
        }

        if (UdevEventPublisher::getValue(device.get(),
                                         "ID_PCI_CLASS_FROM_DATABASE") ==
            "Mass storage controller") {
          std::string driverName =
              UdevEventPublisher::getValue(device.get(), "DRIVER");

          auto i = std::lower_bound(results.begin(), results.end(), driverName);
          if (i == results.end() || driverName < *i) {
            results.insert(i, driverName);
          }
        }
      });

  return results;
}

void getSmartCtlDeviceType(std::vector<std::string> const& storageDrivers,
                           std::vector<explicitDevice>& types) {
  for (auto const& driver : storageDrivers) {
    try {
      explicitDevice dev;
      dev = kExplicitDriverToDevice.at(driver);
      types.push_back(dev);
    } catch (std::out_of_range) {
    }
  }
}

void walkSmartDevices(std::function<void(libsmartctl::Client&,
                                         std::string const& devname,
                                         std::string const& type,
                                         int deviceId)> handleDevF) {
  if (getuid() || geteuid()) {
    LOG(WARNING) << "Need root access for smart information";
  }

  QueryData results;
  libsmartctl::Client& c = libsmartctl::Client::getClient();

  std::vector<std::string> storageDrivers = getStorageCtlerClassDrivers();

  std::vector<explicitDevice> types;
  getSmartCtlDeviceType(storageDrivers, types);

  std::vector<std::string> devs = getBlkDevices();
  for (auto const& dev : devs) {
    bool found = false;
    for (auto const& type : types) {
      // If type is not null can skip the partitions
      // THIS ASSUMPTION IS NO LONGER VALID see
      // `nyc3nas10.nyc3.internal.digitalocean.com`
      // if (dev.find_first_of("0123456789") != std::string::npos) {
      //   continue;
      // }

      for (size_t i = 0; i <= type.maxID; i++) {
        std::string fullType = type.driver + std::to_string(i);

        libsmartctl::CantIdDevResp cantId = c.cantIdDev(dev, fullType);
        if (cantId.err != NOERR) {
          LOG(WARNING) << "Error while trying to identify device";
          continue;
        }
        // If device is not identifiable, the type is invalid, skip
        if (!cantId.content) {
          found = true;
          handleDevF(c, dev, fullType, i);
        }
      }
      // If found, break out of types.
      if (found) {
        break;
      }
    }
    // If none of the initial devices types work, we try auto detetction.
    if (!found) {
      handleDevF(c, dev, "", -1);
    }
  }
}

QueryData genSmartDevInformation(QueryContext& context) {
  QueryData results;

  walkSmartDevices([&results](libsmartctl::Client& c,
                              const std::string& dev,
                              std::string const& type,
                              int i) {
    libsmartctl::DevInfoResp resp = c.getDevInfo(dev, type);
    if (resp.err != NOERR) {
      LOG(WARNING) << "There was an error retrieving drive information: "
                   << resp.err;
      return;
    }

    if (i > -1) {
      resp.content["device_id"] = std::to_string(i);
    }

    resp.content["device_name"] = dev;
    results.push_back(resp.content);
  });

  return results;
}

QueryData genSmartDevVendorAttrs(QueryContext& context) {
  QueryData results;

  walkSmartDevices([&results](libsmartctl::Client& c,
                              const std::string& dev,
                              std::string const& type,
                              int i) {
    libsmartctl::DevVendorAttrsResp resp = c.getDevVendorAttrs(dev, type);
    if (resp.err != NOERR) {
      LOG(WARNING)
          << "There was an error retrieving smart drive vendor attributes: "
          << resp.err;
      return;
    }
    // Walk thru attributes to append device name to each vendor attribute map
    // and append to results.
    for (auto& va : resp.content) {
      if (i > -1) {
        va["device_id"] = std::to_string(i);
      }

      va["device_name"] = dev;
      results.push_back(va);
    }
  });

  return results;
}
}
}
