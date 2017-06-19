/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "boost/date_time/posix_time/posix_time.hpp"
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_posix.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmiif.h>
#include <boost/asio.hpp>
#include <boost/chrono.hpp>

namespace osquery {
namespace tables {

/* ============================ IPMIClient core  ==============================
 */

static void timeout(size_t timeoutMS = 500) {
  boost::asio::io_service io_service;
  boost::asio::deadline_timer timer(io_service);
  timer.expires_from_now(boost::posix_time::milliseconds(timeoutMS));
  timer.wait();
}

const auto kFreeOSHandle = [](os_handler_t* h) {
  if (h != nullptr) {
    h->free_os_handler(h);
  }
};

class IPMIClient {
 public:
  static IPMIClient& get();

 public:
  void setDomain(ipmi_domain_t* d);

  void iterateEntities(ipmi_entities_iterate_entity_cb cb, QueryData& data);

  bool up();

  ~IPMIClient();
  IPMIClient(IPMIClient const& client) = delete;
  void operator=(IPMIClient const& client) = delete;

 private:
  IPMIClient();

  std::atomic<bool> running_;
  std::atomic<bool> up_;

  std::atomic<ipmi_domain_t*> domain_;

  std::unique_ptr<os_handler_t, std::function<void(os_handler_t*)>> os_hnd_;

  std::future<void> bg_;
};

void ipmiLogger(os_handler_t* handler,
                const char* format,
                enum ipmi_log_type_e logType,
                va_list ap) {
  size_t max = 1024;
  char buf[max];

  switch (logType) {
  case IPMI_LOG_SEVERE:
  case IPMI_LOG_FATAL:
  case IPMI_LOG_ERR_INFO:
    vsnprintf(buf, max, format, ap);
    LOG(ERROR) << buf;
    break;
  default:
    // Suppress all other log levels
    break;
  }
}

void IPMIFullyUpCB(ipmi_domain_t* domain, void* data) {
  IPMIClient* c = (IPMIClient*)data;
  c->setDomain(domain);
  return;
}

IPMIClient& IPMIClient::get() {
  static IPMIClient c;
  return c;
}

bool IPMIClient::up() {
  return up_.load();
}

IPMIClient::~IPMIClient() {
  running_.store(false);
  up_.store(false);
}

IPMIClient::IPMIClient()
    : running_(false),
      up_(false),
      domain_(nullptr),
      os_hnd_(nullptr, kFreeOSHandle) {
  LOG(WARNING) << "Initiating IPMI client for the first time.  This could take "
                  "a couple minutes.";

  std::unique_ptr<os_handler_t, std::function<void(os_handler_t*)>> tempHandle(
      ipmi_posix_setup_os_handler(), kFreeOSHandle);
  if (tempHandle.get() == nullptr) {
    LOG(ERROR)
        << "Could not allocate posix handler with ipmi_posix_setup_os_handler";
    return;
  }
  os_hnd_.swap(tempHandle);

  os_hnd_.get()->set_log_handler(os_hnd_.get(), ipmiLogger);

  int rv = ipmi_init(os_hnd_.get());
  if (rv != 0) {
    LOG(ERROR) << "IPMI initialization failed: " << strerror(rv);
    return;
  }

  // Only support 1 IPMI connection for now..
  ipmi_con_t* con;
  rv = ipmi_smi_setup_con(0, os_hnd_.get(), NULL, &con);
  if (rv != 0) {
    LOG(WARNING) << "Error setting up SMI connection: " << strerror(rv);
    return;
  }

  // Open domain
  if (ipmi_open_domain(
          "", &con, 1, NULL, NULL, IPMIFullyUpCB, this, NULL, 0, NULL) != 0) {
    LOG(ERROR) << "Error opening IPMI domain: " << strerror(rv);
    return;
  }

  up_.store(true);
  running_.store(true);
  bg_ = std::async(std::launch::async, [&]() {
    while (running_.load() == true) {
      os_hnd_.get()->perform_one_op(os_hnd_.get(), NULL);
    }
  });
}

void IPMIClient::setDomain(ipmi_domain_t* d) {
  domain_.store(d);
}

void IPMIClient::iterateEntities(ipmi_entities_iterate_entity_cb cb,
                                 QueryData& data) {
  while (domain_.load() == nullptr) {
  }

  int rv = ipmi_domain_iterate_entities(domain_, cb, &data);
  if (rv != 0) {
    LOG(ERROR)
        << "Could not register callback for ipmi_domain_iterate_entities: "
        << strerror(rv);
    return;
  }
}

/* =============================== FRU Table ===================================
 */

void traverseFRUNodeTree(ipmi_fru_node_t* node, Row& row) {
  time_t time;
  enum ipmi_fru_data_type_e dtype;
  double floatval = 0;
  int intval = 0;
  unsigned int dataLen = 0;
  const char* name = nullptr;

  for (size_t i = 0;; i++) {
    char* data = nullptr;
    std::unique_ptr<char, std::function<void(char*)>> sData(data,
                                                            ipmi_fru_data_free);

    ipmi_fru_node_t* subnode = nullptr;
    std::unique_ptr<ipmi_fru_node_t, std::function<void(ipmi_fru_node_t*)>>
        sNode(subnode, ipmi_fru_put_node);
    int rv = ipmi_fru_node_get_field(node,
                                     i,
                                     &name,
                                     &dtype,
                                     &intval,
                                     &time,
                                     &floatval,
                                     &data,
                                     &dataLen,
                                     &subnode);
    if (rv == EINVAL) {
      break;
    }

    if (rv != 0) {
      continue;
    }

    std::string colName = "";
    if (name == nullptr) {
      colName = "missing[" + std::to_string(i) + "]";
    } else {
      colName = name;
    }

    switch (dtype) {
    case IPMI_FRU_DATA_INT:
      row[colName] = INTEGER(intval);
      break;

    case IPMI_FRU_DATA_TIME:
      row[colName] = BIGINT(time);
      break;

    case IPMI_FRU_DATA_ASCII:
      row[colName] = data;
      break;

    case IPMI_FRU_DATA_BOOLEAN:
      row[colName] = INTEGER(intval);
      break;

    case IPMI_FRU_DATA_FLOAT:
      row[colName] = std::to_string(floatval);
      break;

    case IPMI_FRU_DATA_SUB_NODE:
      traverseFRUNodeTree(subnode, row);
      break;

    default:
      // Do not handle binary and unicode types
      break;
    }
  }
}

void getFRUCB(ipmi_entity_t* entity, void* data) {
  QueryData* result = (QueryData*)data;

  ipmi_fru_t* fru = ipmi_entity_get_fru(entity);
  if (fru == nullptr) {
    return;
  }

  Row r;
  r["id"] = INTEGER(ipmi_entity_get_entity_id(entity));
  r["instance"] = INTEGER(ipmi_entity_get_entity_instance(entity));

  ipmi_fru_node_t* node = nullptr;
  std::unique_ptr<ipmi_fru_node_t, std::function<void(ipmi_fru_node_t*)>> _(
      node, ipmi_fru_put_node);

  const char* type = "";
  int rv = ipmi_fru_get_root_node(fru, &type, &node);
  if (rv != 0) {
    // Consider dropping this log message.
    LOG(ERROR) << "Could not get FRU root node: " << strerror(rv);
    return;
  }

  r["type"] = type;
  traverseFRUNodeTree(node, r);
  result->push_back(r);
}

QueryData genIPMIFRUs(QueryContext& context) {
  QueryData results;

  IPMIClient& c = IPMIClient::get();
  if (!c.up()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.iterateEntities(getFRUCB, results);

  return results;
}

/*
=============================== SDR INFO ====================================*/

std::string getSensorThresholdSuffix(ipmi_sensor_t* sensor) {
  size_t suffixLen = 50;
  char suffix[suffixLen];

  const char* percent = "";
  const char* base;
  const char* mod_use = "";
  const char* modifier = "";
  const char* rate;
  base = ipmi_sensor_get_base_unit_string(sensor);
  if (ipmi_sensor_get_percentage(sensor))
    percent = "%";
  switch (ipmi_sensor_get_modifier_unit_use(sensor)) {
  case IPMI_MODIFIER_UNIT_NONE:
    break;
  case IPMI_MODIFIER_UNIT_BASE_DIV_MOD:
    mod_use = "/";
    modifier = ipmi_sensor_get_modifier_unit_string(sensor);
    break;
  case IPMI_MODIFIER_UNIT_BASE_MULT_MOD:
    mod_use = "*";
    modifier = ipmi_sensor_get_modifier_unit_string(sensor);
    break;
  }
  rate = ipmi_sensor_get_rate_unit_string(sensor);

  snprintf(
      suffix, suffixLen, "%s %s%s%s%s", percent, base, mod_use, modifier, rate);

  return suffix;
}

void readThresholdSensorCB(ipmi_sensor_t* sensor,
                           int err,
                           enum ipmi_value_present_e value_present,
                           unsigned int raw_value,
                           double val,
                           ipmi_states_t* states,
                           void* data) {
  if (err != 0) {
    LOG(ERROR) << "Could not read sensor: " << strerror(err);
    return;
  }

  Row r;

  int maxChar = 256;
  char name[maxChar];
  int rv = ipmi_sensor_get_name(sensor, name, maxChar);
  if (rv < 1) {
    r["name"] = "missing";

  } else {
    r["name"] = name;
  }

  r["sensor_type"] = ipmi_sensor_get_sensor_type_string(sensor);
  r["sensor_reading_type"] = ipmi_sensor_get_event_reading_type_string(sensor);
  r["sensor_is_threshold"] = "1";

  switch (value_present) {
  case IPMI_NO_VALUES_PRESENT:
    r["value"] = "no reading available";
    break;

  case IPMI_RAW_VALUE_PRESENT:
    r["value"] = std::to_string(raw_value);
    break;

  default:
    r["value"] = std::to_string(val) + getSensorThresholdSuffix(sensor);
  }

  r["threshold_out_of_range"] =
      (ipmi_is_threshold_out_of_range(states, IPMI_LOWER_NON_CRITICAL) ||
       ipmi_is_threshold_out_of_range(states, IPMI_UPPER_NON_CRITICAL))
          ? "1"
          : "0";

  QueryData* results = (QueryData*)data;
  results->push_back(r);
}

void getThresholdSensorCB(ipmi_entity_t* entity, void* data) {
  ipmi_entity_iterate_sensors(
      entity,
      [](ipmi_entity_t* ent, ipmi_sensor_t* sensor, void* data) {
        if (ipmi_sensor_get_event_reading_type(sensor) ==
            IPMI_EVENT_READING_TYPE_THRESHOLD) {
          int rv = ipmi_sensor_get_reading(sensor, readThresholdSensorCB, data);
          if (rv != 0) {
            LOG(ERROR) << "Could not get sensor reading: " << strerror(rv);
          }
        }
      },
      data);
}

QueryData genIPMIThresholdSensors(QueryContext& context) {
  QueryData results;

  IPMIClient& c = IPMIClient::get();
  if (!c.up()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.iterateEntities(getThresholdSensorCB, results);

  std::future<void> bg = std::async(std::launch::async, timeout, 500);

  bg.get();
  return results;
}

/*================================ MC Table ===================================
 */

void iterateMCsCB(ipmi_domain_t* domain, ipmi_mc_t* mc, void* data) {
  QueryData* result = (QueryData*)data;
  Row r;
  char name[IPMI_MC_NAME_LEN];

  int len = ipmi_mc_get_name(mc, name, IPMI_MC_NAME_LEN);
  if (len > 0) {
    r["name"] = name;
  }

  r["device_id"] = INTEGER(ipmi_mc_device_id(mc));
  r["device_revision"] = INTEGER(ipmi_mc_device_revision(mc));
  r["device_available"] = INTEGER(ipmi_mc_device_available(mc));
  r["firmware_major_version"] = INTEGER(ipmi_mc_major_fw_revision(mc));
  r["firmware_minor_version"] = INTEGER(ipmi_mc_minor_fw_revision(mc));
  r["ipmi_major_version"] = INTEGER(ipmi_mc_major_version(mc));
  r["ipmi_minor_version"] = INTEGER(ipmi_mc_minor_version(mc));
  r["iana_manufacturer_id"] = INTEGER(ipmi_mc_manufacturer_id(mc));
  r["product_id"] = INTEGER(ipmi_mc_product_id(mc));
  r["provides_device_sdrs"] = INTEGER(ipmi_mc_provides_device_sdrs(mc));
  r["chassis_support"] = INTEGER(ipmi_mc_chassis_support(mc));
  r["bridge_support"] = INTEGER(ipmi_mc_bridge_support(mc));
  r["ipmb_event_generator_support"] =
      INTEGER(ipmi_mc_ipmb_event_generator_support(mc));
  r["ipmb_event_reciever_support"] =
      INTEGER(ipmi_mc_ipmb_event_receiver_support(mc));
  r["fru_inventory_support"] = INTEGER(ipmi_mc_fru_inventory_support(mc));
  r["sel_device_support"] = INTEGER(ipmi_mc_sel_device_support(mc));
  r["sdr_respository_support"] = INTEGER(ipmi_mc_sdr_repository_support(mc));
  r["sensor_device_support"] = INTEGER(ipmi_mc_sensor_device_support(mc));
  r["is_active"] = INTEGER(ipmi_mc_is_active(mc));

  unsigned char guid = 0;
  int rv = ipmi_mc_get_guid(mc, &guid);
  if (rv == 0) {
    r["guid"] = INTEGER(guid);
  }

  result->push_back(r);
}

void getMCsCB(ipmi_entity_t* entity, void* data) {
  ipmi_domain_iterate_domains(
      [](ipmi_domain_t* domain, void* data) {
        int rv = ipmi_domain_iterate_mcs(domain, iterateMCsCB, data);
        if (rv != 0) {
          LOG(ERROR) << "Could not register MC update callback: "
                     << strerror(rv);
        }
      },
      data);
}

QueryData genIPMIMCs(QueryContext& context) {
  QueryData results;
  IPMIClient& c = IPMIClient::get();
  if (!c.up()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.iterateEntities(getMCsCB, results);

  std::future<void> bg = std::async(std::launch::async, timeout, 200);

  bg.get();
  return results;
}

} // namespace tables
} // namespace osquery
