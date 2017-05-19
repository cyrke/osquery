/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <linux/raid/md_p.h>
#include <linux/raid/md_u.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "osquery/tables/system/linux/md_tables.h"

using namespace testing;

namespace osquery {
namespace tables {

class MockMD : public MDInterface {
 public:
  MOCK_METHOD2(getDiskInfo, bool(std::string, mdu_disk_info_t&));
  MOCK_METHOD2(getArrayInfo, bool(std::string, mdu_array_info_t&));
  MOCK_METHOD2(parseMDStat, void(std::vector<std::string>, MDStat&));
  MOCK_METHOD1(getPathByDevName, std::string(std::string));
  MOCK_METHOD2(getDevName, std::string(int, int));
};

class GetDrivesForArrayTest : public ::testing::Test {};

mdu_disk_info_t getDiskInfo(
    int number, int raidDisk, int state, int major, int minor) {
  mdu_disk_info_t diskInfo;

  diskInfo.number = number;
  diskInfo.raid_disk = raidDisk;
  diskInfo.state = state;
  diskInfo.major = major;
  diskInfo.minor = minor;

  return diskInfo;
}

/**
 * @brief Engine for testing getDrivesForArray
 *
 * @param arrayName name of the array to pass to getDrivesForArray
 * @param arrayRaidDisks number of raid disks of the array to be returned by
 * ioctl
 * @param blkDevicePrefix the prefix for the block device of disk, with expected
 * name to be prefix push the disk number
 * @param targetDisks the target disks that will return custom mdu_disk_info_t
 * @param got reference to QueryData to be passed to to getDrivesForArray
 */
void GetDrivesForArrayTestHarness(std::string arrayName,
                                  int arrayRaidDisks,
                                  std::string blkDevicePrefix,
                                  std::map<int, mdu_disk_info_t> targetDisks,
                                  QueryData& got) {
  MockMD md;
  std::string arrayDevPath = "/dev/" + arrayName;

  EXPECT_CALL(md, getPathByDevName(_)).WillOnce(Return(arrayDevPath));

  mdu_array_info_t arrayInfo;
  arrayInfo.raid_disks = arrayRaidDisks;
  EXPECT_CALL(md, getArrayInfo(arrayDevPath, _))
      .WillOnce(DoAll(SetArgReferee<1>(arrayInfo), Return(true)));

  Sequence::Sequence s1, s2;
  for (int i = 0; i < MD_SB_DISKS; i++) {
    mdu_disk_info_t diskInfo;
    diskInfo.number = i;
    if (targetDisks.find(i) != targetDisks.end()) {
      EXPECT_CALL(md, getDiskInfo(arrayDevPath, _))
          .InSequence(s1)
          .WillOnce(DoAll(SetArgReferee<1>(targetDisks[i]), Return(true)));

      EXPECT_CALL(md, getDevName(targetDisks[i].major, targetDisks[i].minor))
          .InSequence(s1)
          .WillOnce(Return(blkDevicePrefix + std::to_string(i)));

    } else {
      diskInfo.raid_disk = -1;
      diskInfo.state = 8;
      diskInfo.major = 0;
      diskInfo.minor = 0;
      EXPECT_CALL(md, getDiskInfo(arrayDevPath, _))
          .InSequence(s1)
          .WillOnce(DoAll(SetArgReferee<1>(diskInfo), Return(true)));
    }
  }

  getDrivesForArray(arrayName, md, got);
}

TEST_F(GetDrivesForArrayTest, all_drives_healthy) {
  int majorAddend = 5;
  int minorAddend = 10;
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;
  for (int i = 0; i < 6; i++) {
    int major = i + majorAddend;
    int minor = i + minorAddend;

    targets[i] = getDiskInfo(i, i, 6, major, minor);
  }

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "active sync"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "active sync"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "active sync"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
  };

  EXPECT_EQ(got, expected);
}

TEST_F(GetDrivesForArrayTest, all_drives_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";
  std::map<int, mdu_disk_info_t> targets;
  std::string arrayName = "md0";
  QueryData got;

  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "removed"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "removed"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "removed"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "removed"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "removed"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "removed"},
          {"slot", "5"},
      },
  };
};

TEST_F(GetDrivesForArrayTest, all_drives_faulty) {
  int majorAddend = 5;
  int minorAddend = 10;
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;
  for (int i = 0; i < 6; i++) {
    int major = i + majorAddend;
    int minor = i + minorAddend;

    targets[i] = getDiskInfo(i, i, 1, major, minor);
  }

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "faulty"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "faulty"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "faulty"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "faulty"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "faulty"},
          {"slot", "5"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, every_other_drives_faulty) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;

  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[5] = getDiskInfo(5, 5, 6, 9, 10);
  targets[0] = getDiskInfo(0, -1, 1, 11, 12);
  targets[2] = getDiskInfo(2, -1, 1, 13, 14);
  targets[4] = getDiskInfo(4, -1, 1, 15, 16);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "faulty"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "faulty"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, some_drives_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;

  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[5] = getDiskInfo(5, 5, 6, 9, 10);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {

      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "4"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, some_faulty_some_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;
  targets[0] = getDiskInfo(0, -1, 1, 5, 6);
  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[4] = getDiskInfo(4, 4, 6, 5, 6);
  targets[5] = getDiskInfo(5, -1, 1, 9, 10);
  targets[6] = getDiskInfo(6, 0, 6, 11, 12);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "active sync"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "faulty"},
          {"slot", "5"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "6"},
          {"state", "active sync"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "2"},
      },
  };

  EXPECT_EQ(got, expected);
};

/* This is a very interesting test, in that it validates the inability of code
 * to predict which exactly which slot a removed or faulty drive belonged to if
 * there are multiple faulties and/or removed and the mdu_disk_info_t number is
 * greater than the number of RAID disks*/
TEST_F(GetDrivesForArrayTest, scattered_faulty_and_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;

  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[5] = getDiskInfo(5, 5, 6, 9, 10);
  targets[9] = getDiskInfo(9, -1, 1, 13, 14);
  targets[17] = getDiskInfo(17, -1, 1, 15, 16);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "9"},
          {"state", "faulty"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "17"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "4"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, arrayInfo_ioctl_error) {
  MockMD md;
  std::string arrayDevPath = "/dev/md0";

  EXPECT_CALL(md, getPathByDevName(_)).WillOnce(Return(arrayDevPath));
  EXPECT_CALL(md, getArrayInfo(arrayDevPath, _)).WillOnce(Return(false));

  QueryData got;
  getDrivesForArray("md0", md, got);

  EXPECT_TRUE(got.size() == 0);
};

} // namespace tables
} // namespace osquery
