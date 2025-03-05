/* * Copyright 2025.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Francois-R.Boyer@PolyMtl.ca
 *
 */

// Compile with: g++ test_pcap.cpp -lpcap
// (important to have -l after the source using it.

#include <pcap/pcap.h>
#include <iostream>
#include <thread>
#include <vector>
#include <span>
#include "pcap_mock.hpp"
using namespace std;

int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_create("lo", errbuf);
	if (handle == nullptr) {
		cout << "pcap_create error: " << errbuf << endl;
		return 1;
	}
	cout << "no error: " << pcap_statustostr(0) << endl;
	if (auto error = pcap_set_promisc(handle, true)) {
		cout << "pcap_set_promisc error: " << pcap_statustostr(error) << endl;
	}
	if (auto error = pcap_activate(handle)) {
		cout << "pcap_activate error: " << pcap_statustostr(error) << endl;
	}
	int fd = pcap_get_selectable_fd(handle);
	fd_set the_fd_set; FD_ZERO(&the_fd_set);
	FD_SET(fd, &the_fd_set);
	timeval timeout = { .tv_sec=1, .tv_usec=0 };
	thread simulate_arriving_packets([=]() {
		this_thread::sleep_for(0.5s);
		pcap_mock::simulate_packets_received(handle,
			vector<vector<u_char>>{vector<u_char>{1,3,3,7}});
	});
	int selected_count = select(fd+1, &the_fd_set, nullptr, nullptr, &timeout);
	cout << "selected_count: " << selected_count << endl;
	if (selected_count > 0) {
		if (FD_ISSET(fd, &the_fd_set)) {
			pcap_pkthdr* hdr; const u_char* data;
			pcap_next_ex(handle, &hdr, &data);
			cout << hdr->len << endl;
			for (int v : span(data, hdr->len)) {
				cout << v << " ";
			}
			cout << endl;
		}
	}

	pcap_close(handle);
	simulate_arriving_packets.join();
	cout << "ok" << endl;
}
// vi: ts=4
