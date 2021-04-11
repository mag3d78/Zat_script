from zat import zeek_log_reader;
import datetime

#from zat.utils import vt_query;
#import tldextract;

print("---> Zeek log reader start ---");

time_cur = datetime.datetime.now();
print("---> Current time: ", time_cur);
# vtq = vt_query.VTQuery();

query_stat = {}
# read log file
reader = zeek_log_reader.ZeekLogReader('/usr/local/zeek/logs/current/dns.log', tail=True);


for row in reader.readrows():
    query = row.get('query');
    if (query != '-') :
        time_cur = datetime.datetime.now();
        value = query_stat.get(query, 0);
        value = value + 1;
        query_stat[query] = value;
        print(time_cur, " -> ", query, " -> total count: ", value);

        #query = tldextract.extract(query).suffix;
        #answer = vtq.query_url(query);
        #print(' -> ', answer);


print("-- Zeek log reader stop ---");

