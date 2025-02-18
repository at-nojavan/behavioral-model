#include <gtest/gtest.h>

#include <bm/bm_apps/packet_pipe.h>
#include <bm/bm_sim/dev_mgr.h>
#include "src/BMI/bmi_interface.h"
#include "src/BMI/BMI/bmi_port.h"

#include <memory>
#include <vector>
#include <algorithm>  // for std::fill_n

#include <boost/filesystem.hpp>

#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <bm/bm_sim/dev_mgr.h>
#include <functional>
#include <string>
#include <random>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/time.h>
#include <iostream>


#include "simple_switch.h"
#include "bm/bm_sim/packet_handler.h"

#include "utils.h"

namespace fs = boost::filesystem;

using bm::MatchErrorCode;
using bm::ActionData;
using bm::MatchKeyParam;
using bm::entry_handle_t;

namespace {

void
packet_handler(int port_num, const char *buffer, int len, void *cookie) {
  static_cast<SimpleSwitch *>(cookie)->receive(port_num, buffer, len);
}

}  // namespace

class TestSwitch : public SimpleSwitch{
  public:

    std::vector<PacketInfo> received_data;

    explicit TestSwitch(bool enable_swap = false, port_t drop_port = default_drop_port, size_t nb_queues_per_port = default_nb_queues_per_port);

    int receive_with_metadata_(port_t port_num, const char *buffer, int len, MyMetadata metadata) override{
      // std::cout << "inside receive_with_metadata_";
      PacketInfo packet_info = {port_num, buffer, len, metadata};
      received_data.push_back(packet_info);
      return 0;
    }


};

TestSwitch::TestSwitch(bool enable_swap, port_t drop_port,
                           size_t nb_queues_per_port)
  : SimpleSwitch(enable_swap){
};

// new test port

typedef struct bmi_port_s {
  bmi_interface_t *bmi;
  int port_num;
  char *ifname;
  int fd;
  pthread_mutex_t stats_lock;
  bmi_port_stats_t stats;
} bmi_port_t;

typedef struct bmi_port_mgr_s {
  bmi_port_t *ports; // sorted by port number
  int port_count;
  int max_port_count;
  int socketpairfd[2];
  fd_set fds;
  int max_fd;
  void *cookie;
  PacketHandlerWithPacketInfo packet_handler;
  pthread_t select_thread;
  /* We use a RW mutex to protect port_mgr and port state. Send & receive will
  acquire a read lock, while port_add and port_remove will acquire a write
  lock. Using a single mutex for the port_mgr is much easier than having one for
  each port, even though it means that adding / removing a port will block send
  & receive for all ports. */
  pthread_rwlock_t lock;
} bmi_port_mgr_t;

typedef struct bmi_port_s bmi_port_t;

typedef struct bmi_port_mgr_s bmi_port_mgr_t;

PacketHandlerWithPacketInfo test_packet_handler;

int test_set_packet_handler_with_packet_info(bmi_port_mgr_t *port_mgr, const PacketHandlerWithPacketInfo &handler) {
  // pthread_rwlock_wrlock(&port_mgr->lock);
  // std::cout << "\ninside test_set_packet_handler_with_packet_info\n";
  test_packet_handler = handler;
  // port_mgr->packet_handler = handler;
  // pthread_rwlock_unlock(&port_mgr->lock);
  return 0;
}

namespace bm {

// new device manager

class TestDevMgrImp : public DevMgrIface {
 public:
  TestDevMgrImp() {
  // from test_recirc:
    // p_monitor = PortMonitorIface::make_active(0);
    
    // from test_switch:
    p_monitor = PortMonitorIface::make_dummy();
  }

  ~TestDevMgrImp() override {}

  private:
  bool port_is_up_(port_t port) const override {
    (void) port;
    // std::lock_guard<std::mutex> lock(status_mutex);
    // auto it = port_status.find(port);
    // bool exists = (it != port_status.end());

    // return (exists && ((it->second == PortStatus::PORT_ADDED) ||
    //                    (it->second == PortStatus::PORT_UP)));
  }

  std::map<port_t, PortInfo> get_port_info_() const override {
    return {};
  }

  void start_() override {
    // assert(port_mgr);
    // if (bmi_start_mgr(port_mgr))
      // Logger::get()->critical("Could not start BMI port manager");
  }

  ReturnCode port_add_(const std::string &iface_name, port_t port_num,
                       const PortExtras &port_extras) override {
    (void) iface_name;
    (void) port_extras;
    // std::lock_guard<std::mutex> lock(status_mutex);
    // auto it = port_status.find(port_num);
    // if (it != port_status.end()) return ReturnCode::ERROR;
    // port_status.insert(std::make_pair(port_num, PortStatus::PORT_ADDED));
    return ReturnCode::SUCCESS;
  }

  ReturnCode port_remove_(port_t port_num) override {
    (void) port_num;
    // std::lock_guard<std::mutex> lock(status_mutex);
    // auto it = port_status.find(port_num);
    // if (it == port_status.end()) return ReturnCode::ERROR;
    // port_status.erase(it);
    return ReturnCode::SUCCESS;
  }

  ReturnCode set_packet_handler_(const PacketHandler &handler, void *cookie)
      override {
    // std::cout << "\ninside set_packet_handler_\n";
    // if (test_set_packet_handler_with_packet_info(port_mgr,[handler, cookie](const PacketInfo *packetInfo) { handler(packetInfo->port_num, packetInfo->buffer, packetInfo->len, cookie); })) {

    //   // Logger::get()->critical("Could not set BMI packet handler");
    //   return ReturnCode::ERROR;
    // }
    return ReturnCode::SUCCESS;
  }

  ReturnCode set_packet_handler_with_packet_info_(const PacketHandlerWithPacketInfo &handler)
      override {
    test_set_packet_handler_with_packet_info(port_mgr, handler);
    // if (test_set_packet_handler_with_packet_info(port_mgr, handler)) {
    //   // Logger::get()->critical("Could not set BMI packet handler");
    //   return ReturnCode::ERROR;
    // }
    return ReturnCode::SUCCESS;
  }

  // add simulated receive packet that just calls packet handler
  void simulated_receive(PacketInfo temp_packet){
    test_packet_handler(&temp_packet);
  }

  // int test_set_packet_handler_with_packet_info(bmi_port_mgr_t *port_mgr, const PacketHandlerWithPacketInfo &handler) {
  //   // pthread_rwlock_wrlock(&port_mgr->lock);
  //   port_mgr->packet_handler = handler;
  //   // pthread_rwlock_unlock(&port_mgr->lock);
  //   return 0;
  // }

  void transmit_fn_(DevMgrIface::port_t port_num, const char *buffer, int len)
  override {
    (void)port_num;
    (void)buffer;
    (void)len;
  }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<std::mutex>;

  bmi_port_mgr_t *port_mgr{nullptr};
  mutable Mutex mutex;
};


class SwitchWithInfo_RecircP4 : public ::testing::Test {
 protected:
  static constexpr size_t kMaxBufSize = 512;

  static constexpr bm::device_id_t device_id{0};

  SwitchWithInfo_RecircP4()
      // : packet_inject(packet_in_addr)
      { }

  static void SetUpTestCase() {
    // from test_switch:
    std::unique_ptr<TestDevMgrImp> my_dev_mgr(new TestDevMgrImp());
    test_switch = std::make_unique<TestSwitch>();
    int argc = 2;
    char argv0[] = "switch_test";
    char argv1[] = "--no-p4";
    char *argv[] = {argv0, argv1};
    test_switch->init_from_command_line_options(argc, argv, nullptr, nullptr, std::move(my_dev_mgr));


    // get the raw pointer to the object of devmger. because we have to call simulated receive in the test. for that we have to know where the devmgr is.

    // test_switch.start_and_return();
  }

  // Per-test-case tear-down.
  static void TearDownTestCase() {
    test_switch= nullptr;
  }


  virtual void SetUp() {
    // packet_inject.start();
    // auto cb = std::bind(&PacketInReceiver::receive, &receiver,
    //                     std::placeholders::_1, std::placeholders::_2,
    //                     std::placeholders::_3, std::placeholders::_4);
    // packet_inject.set_packet_receiver(cb, nullptr);

    // // default actions for all tables
    // test_switch->mt_set_default_action(0, "t_ingress", "_nop", ActionData());
  }

  virtual void TearDown() {
    // kind of experimental, so reserved for testing
    // test_switch->reset_state();
  }

 protected:
  static const char packet_in_addr[];
  static std::unique_ptr<TestSwitch> test_switch;
  // bm_apps::PacketInject packet_inject;
  PacketInReceiver receiver{};

 private:
  static const char testdata_dir[];
  static const char test_json[];
};

const char SwitchWithInfo_RecircP4::packet_in_addr[] =
    "inproc://packets";

std::unique_ptr<TestSwitch> SwitchWithInfo_RecircP4::test_switch = nullptr;

const char SwitchWithInfo_RecircP4::testdata_dir[] = TESTDATADIR;
const char SwitchWithInfo_RecircP4::test_json[] =
    "recirc.json";

std::string generate_random_string(int length) {
    std::string all_chars;
    for (int i = 0; i < 256; ++i) {
        all_chars += static_cast<char>(i);
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, static_cast<int>(all_chars.size()) - 1);

    std::string result;
    for (int i = 0; i < length; ++i) {
        result += all_chars[dis(gen)];
    }

    return result;
}

TEST_F(SwitchWithInfo_RecircP4, testing_packet_handler) {

  const char *pkt_data = "";
  std::vector<PacketInfo> test_data;

  // char buffer[101];
  // std::string generated_string = generate_random_string(50);
  // strncpy(buffer, generated_string.c_str(), sizeof(buffer) - 1);
  // buffer[sizeof(buffer) - 1] = '\0';
  // pkt_data = buffer;
  // std::cout << "\nstat\n" ; 
  // std::cout << "\ntesting random packet data1:" <<pkt_data;
  
  pkt_data = "testing string 0";
  PacketInfo temp_packet = {
    .port_num = 2,
    .buffer = pkt_data,
    .len = 28,
    .metadata = {127}
  };
  test_data.push_back(temp_packet);


  // generated_string = generate_random_string(50);
  // strncpy(buffer, generated_string.c_str(), sizeof(buffer) - 1);
  // buffer[sizeof(buffer) - 1] = '\0';
  // pkt_data = buffer;
  // std::cout << "\ntesting random packet data2:" <<pkt_data;
  
  pkt_data = "payload for testing purposes";
  temp_packet = {
    .port_num = 4,
    .buffer = pkt_data,
    .len = 55,
    .metadata = {12257}
  };
  test_data.push_back(temp_packet);

  pkt_data = "test packet data for testing the new set_packet_handler functions.";
  temp_packet = {
    .port_num = 8,
    .buffer = pkt_data,
    .len = 128,
    .metadata = {9825457}
  };
  test_data.push_back(temp_packet);

  for (PacketInfo info: test_data){
    test_packet_handler(&info);
  }

    for (unsigned int i = 0; i < test_data.size(); i++) {
      EXPECT_EQ(test_switch->received_data[i].port_num , test_data[i].port_num);
      EXPECT_EQ(test_switch->received_data[i].buffer , test_data[i].buffer);
      EXPECT_EQ(test_switch->received_data[i].len , test_data[i].len);
      EXPECT_EQ(test_switch->received_data[i].metadata.ingress_timestamp , test_data[i].metadata.ingress_timestamp);
    }
  EXPECT_EQ(2,2);
}





} // namespace bm
