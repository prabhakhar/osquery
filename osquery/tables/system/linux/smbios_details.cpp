/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

using namespace std;

namespace osquery {
namespace tables {

	QueryData genSMBIOSDetails(QueryContext &context) {
		Row r;
		QueryData results;
		std::string result = "";

		FILE* pipe = popen("dmidecode -t bios", "r");
		if (!pipe) {
			return results;
		}
		char buf[128];
		while(!feof(pipe)) {
			if(fgets(buf, 128, pipe) != NULL) result += buf;
		}
		pclose(pipe);


		std::stringstream ss(result);
		std::string line;
		while (std::getline(ss, line, '\n')) {
			boost::trim(line);
			if (boost::starts_with(line, "SMBIOS")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(" "));
				string name = all[1];
				boost::trim(name);
				r["SMBIOS"] = name;
			}
			if (boost::starts_with(line, "Vendor")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(":"));
				string name = all[1];
				boost::trim(name);
				r["Vendor"] = name;
			}
			if (boost::starts_with(line, "Version")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(":"));
				string name = all[1];
				boost::trim(name);
				r["BIOS Version"] = name;
			}
			if (boost::starts_with(line, "BIOS Revision")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(" "));
				string name = all[1];
				boost::trim(name);
				r["BIOS Revision"] = name;
			}
			if (boost::starts_with(line, "Firmware Revision")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(" "));
				string name = all[1];
				boost::trim(name);
				r["Firmware Revision"] = name;
			}
			if (boost::starts_with(line, "Release Date")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(" "));
				string name = all[1];
				boost::trim(name);
				r["Release Date"] = name;
			}
			if (boost::starts_with(line, "ROM Size")) {
				vector<string> all;
				boost::split(all, line, boost::is_any_of(" "));
				string name = all[1];
				boost::trim(name);
				r["ROM Size"] = name;
			}

		}
		results.push_back(r);
		return results;
	}
}
}
