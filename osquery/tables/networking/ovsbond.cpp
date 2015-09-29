#include <osquery/tables.h>
#include <iostream>
#include <string>
#include <stdio.h>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <vector>

using namespace std;

namespace osquery {
	namespace tables {
		QueryData genOvsBondDetails(QueryContext &context) {
			Row r;
			QueryData results;
			std::string result = "";

			FILE* pipe = popen("ovs-appctl lacp/show", "r");

			if (!pipe)
				return results;

			char buf[128];
			while(!feof(pipe)) {
				if(fgets(buf, 128, pipe) != NULL)
					result += buf;
			}
			pclose(pipe);
			std::stringstream ss(result);
			std::string line;
			while (std::getline(ss, line, '\n')) {
				boost::trim(line);
				if (boost::starts_with(line, "----")) {
					vector<string> all;
					boost::split(all, line, boost::is_any_of(" "));
					string name = all[1];
					boost::trim(name);
					r["Name"] = name;
				}
				if (boost::starts_with(line, "status")) {
					vector<string> all;
					boost::split(all, line, boost::is_any_of(":"));
					string status = all[1];
					boost::trim(status);
					r["Status"] = status;
				}
				if (boost::starts_with(line, "slave")) {
					vector<string> all;
					boost::split(all, line, boost::is_any_of(":"));
					string slave = all[1];
					boost::trim(slave);
                    r["Slaves"] += slave;
				}
				if (boost::starts_with(line, "sys_id")) {
					vector<string> all;
					boost::split(all, line, boost::is_any_of(" "));
					string sys_id = all[1];
					boost::trim(sys_id);
					r["SysId"] = sys_id;
				}

			}
			results.push_back(r);
			return results;
		}
	}
}
