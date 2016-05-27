"""
parse-httpheaders.py is intended to take a .pcap and output a .TSV for opening in Excel

This script uses the pcapy and impacket libraries.

https://github.com/CoreSecurity/pcapy
https://github.com/CoreSecurity/impacket

Author:      Harold Ogden (haroldogden@gmail.com)
Contributor: Joshua Cannell
"""
import re
import sys
import Tkinter
import tkFileDialog
import datetime
import time

ERROR_MISSING_DEPENDENCY  = -1
ERROR_NO_PCAP_SELECTED    = -2
ERROR_FAILED_PCAPFILEPATH = -3

try:
    import pcapy
    import impacket.ImpactPacket
    import impacket.ImpactDecoder
except ImportError as e:
    print(("ERROR: Missing dependency: {0}".format(e)))
    sys.exit(ERROR_MISSING_DEPENDENCY)

root = Tkinter.Tk()
root.withdraw()
try:
    max_header_count_input = input("Maximum desired headers in HTTP requests. Leave blank for unlimited: ")
    max_header_count_input = int(max_header_count_input)
except:
    max_header_count_input = None
    print("Null or invalid max header count - header count set to unlimited.")
# note - all http responses will be shown if a request to the 4 tuple (src ip, dst ip, src port, dst port)
# has been seen previously

def convert_timefromepoch(epochTimestamp):
    return time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(epochTimestamp))

print("Please select a .pcap file...")
pcap_filepath = tkFileDialog.askopenfilename()
print("Please choose a location for the output .tsv")
output_filepath = tkFileDialog.asksaveasfilename()
if not pcap_filepath:
    print("Please select a file.")
    sys.exit(ERROR_NO_PCAP_SELECTED)
try:
    reader = pcapy.open_offline(pcap_filepath)
except:
    print("Failed to read pcapFilePath - please select a valid .pcap file")
    sys.exit(ERROR_NO_PCAP_SELECTED)

start_time = datetime.datetime.now()
get_tuples = str("") # this will be a list of src_ip:src_port>dst_ip:dst_port that we check responses against before we display them
# here come the regex!
http_request_pattern = re.compile(r'(?s).{54,94}(GET|POST|PUT|HEAD) (([^/]*)\S*(/\S*)) HTTP/1\.[01]((?:(?:(?:\r\n)|\n)[^:]*: [^\r\n]+)*)(?:(?:\r\n)|\n){2}')  # up to max tcp header
http_response_pattern = re.compile(r'(?s).{54,94}HTTP/1\.[01] (\d+)[^\r\n]*((?:(?:(?:\r\n)|\n)[^:]*: [^\r\n]+)*)(?:(?:\r\n)|\n){2}')  # up to max header
# ok, no more regex
frame = 1

decoder = impacket.ImpactDecoder.EthDecoder()
with open(output_filepath, 'w') as outfile:
    #  output the headerrs to the TSV file
    outfile.write("timeStamp\tframe\tsource_address\tsource_port\tdestination_address\tdestination_port\thost\theadercount\tmethod/code\turl/responsemeta\theaders\tuser-agent/content-type\treferer/content-disposition\n")
    while True:
        http_request_header_results = None
        http_response_header_results = None
        try:
            (header, payload) = reader.next()
            if header == None and payload == '':
                break
            http_request_header_results = re.match(http_request_pattern, payload)  # re.match is used to deliberately search only once at the beginning of the string
            if not http_request_header_results:
                http_response_headere_results = re.match(http_response_pattern, payload)
            if http_request_header_results:
                packet = decoder.decode(payload)
                l2 = packet.child()
                if isinstance(l2, impacket.ImpactPacket.IP):
                    l3 = l2.child()
                    if isinstance(l3, impacket.ImpactPacket.TCP):
                        src_ip = str(l2.get_ip_src())
                        dst_ip = str(l2.get_ip_dst())
                        tcp_src_port = str(l3.get_th_sport())
                        tcp_dst_port = str(l3.get_th_dport())
                # grab data out of the regex results groups, then go through the headers looking for goodies
                http_request_method = http_request_header_results.group(1)
                http_request_url = http_request_header_results.group(2)
                http_request_file = http_request_header_results.group(4)
                # the http headers are \r\n delimited by RFC, but \n is also allowed. Split them into their own list:
                http_request_headers = str(http_request_header_results.group(5)).lstrip("\r\n").replace("\"", "%22").split("\n")
                http_request_header_count = http_request_headers.__len__()  # and once split, get a count of the headers
                if max_header_count_input:  # if the user provided an int, this code block is used. The only difference between this and the "else"...
                                         # is that this block checks the count of headers prior to writing to the file and adding to the four-tuple
                                         # variable containing the IPs/ports of the HTTP request
                    if http_request_header_count <= max_header_count_input:
                        # prepare empty strings in case they don't get filled up by looking at the headers
                        http_request_host = str("")
                        http_user_agent = str("")
                        http_request_referrer = str("")
                        http_request_headers_combined = str("\"") # surround the headers with a double-quote so they can be treated as a single value by excel
                        for i in http_request_headers: #  sanitize headers, put special ones into their own variable, put all into a httpResponseHeadersCombined variable
                            if str(i).startswith("Host:"):
                                http_request_host = i.replace("Host: ", "").replace(".", "[.]").rstrip("\r\n")  # don't need to be clickin malware urls
                                http_request_headers_combined = str(http_request_headers_combined + str("Host: " + http_request_host) + "\n")
                            elif str(i).startswith("User-Agent:"):
                                http_user_agent = i.replace("User-Agent: ", "").rstrip("\r\n")
                                http_request_headers_combined = str(http_request_headers_combined + str("User-Agent: " + http_user_agent) + "\n")
                            elif str(i).startswith("Referer:"):
                                http_request_referrer = i.replace("Referer: ", "").replace(".", "[.]").replace("http://", "hxxp[:]//").rstrip("\r\n")
                                http_request_headers_combined = str(http_request_headers_combined + str("Referer: " + http_request_referrer) + "\n")
                            else:
                                http_request_headers_combined = str(http_request_headers_combined + str(i).rstrip("\r\n") + "\n")
                        http_request_headers_combined = str(http_request_headers_combined.rstrip("\n") + "\"") # remove the final newline...
                        #  and add a double-quote to make the TSV treat all headers as a single value.
                        get_tuples = (get_tuples + src_ip + ":" + tcp_src_port + ">" + dst_ip + ":" + tcp_dst_port)  # add this request's src/dst ip/ports to a list
                        # output to the .TSV - all done with the HTTP request!
                        time_stamp = convert_timefromepoch(header.getts()[0])
                        outfile.write(time_stamp + "\t" + str(frame) + "\t" + src_ip + "\t" + tcp_src_port + "\t" + dst_ip + "\t" + tcp_dst_port + "\t" \
                                      + http_request_host + "\t" + str(http_request_header_count) + "\t" + http_request_method \
                                      + "\t" + http_request_url + "\t" + http_request_headers_combined + "\t" \
                                      + http_user_agent + "\t" + http_request_referrer + "\n")
                else:
                    # prepare empty strings in case they don't get filled up by looking at the headers
                    http_request_host = str("")
                    http_user_agent = str("")
                    http_request_referrer = str("")
                    http_request_headers_combined = str("\"") # surround the headers with a double-quote so they can be treated as a single value by excel
                    for i in http_request_headers: #  sanitize headers, put special ones into their own variable, put all into a httpResponseHeadersCombined variable
                        if str(i).startswith("Host:"):
                            http_request_host = i.replace("Host: ", "").replace(".", "[.]").rstrip("\r\n")  # don't need to be clickin malware urls
                            http_request_headers_combined = str(http_request_headers_combined + str("Host: " + http_request_host) + "\n")
                        elif str(i).startswith("User-Agent:"):
                            http_user_agent = i.replace("User-Agent: ", "").rstrip("\r\n")
                            http_request_headers_combined = str(http_request_headers_combined + str("User-Agent: " + http_user_agent) + "\n")
                        elif str(i).startswith("Referer:"):
                            http_request_referrer = i.replace("Referer: ", "").replace(".", "[.]").replace("http://", "hxxp[:]//").rstrip("\r\n")
                            http_request_headers_combined = str(http_request_headers_combined + str("Referer: " + http_request_referrer) + "\n")
                        else:
                            http_request_headers_combined = str(http_request_headers_combined + str(i).rstrip("\r\n") + "\n")
                    http_request_headers_combined = str(http_request_headers_combined.rstrip("\n") + "\"") # remove the final newline...
                    #  and add a double-quote to make the TSV treat all headers as a single value.
                    get_tuples = (get_tuples + src_ip + ":" + tcp_src_port + ">" + dst_ip + ":" + tcp_dst_port)
                    time_stamp = convert_timefromepoch(header.getts()[0])
                    outfile.write(time_stamp + "\t" + str(frame) + "\t" + src_ip + "\t" + tcp_src_port + "\t" + dst_ip + "\t" + tcp_dst_port + "\t" \
                                  + http_request_host + "\t" + str(http_request_header_count) + "\t" + http_request_method \
                                  + "\t" + http_request_url + "\t" + http_request_headers_combined + "\t" \
                                  + http_user_agent + "\t" + http_request_referrer + "\n")
            elif http_response_header_results:  # http response was found!
                response_meta_a = ""  # clearing them variables. Some need to be strings so if they get written to a file, they end up as nothing between the two tabs...
                response_meta_b = ""
                response_meta_c = ""
                http_response_content_disposition = None  # and these are set to "None" so we can check if they exist
                http_response_content_type = None
                http_response_location = None
                packet = decoder.decode(payload)
                l2 = packet.child()
                if isinstance(l2, impacket.ImpactPacket.IP):
                    l3 = l2.child()
                    if isinstance(l3, impacket.ImpactPacket.TCP):
                        src_ip = str(l2.get_ip_src())
                        dst_ip = str(l2.get_ip_dst())
                        tcp_src_port = str(l3.get_th_sport())
                        tcp_dst_port = str(l3.get_th_dport())
                reversed_tuple = (dst_ip + ":" + tcp_dst_port + ">" + src_ip + ":" + tcp_src_port)  # reverse this packet's IPs and ports so we
                                                                                                   # can check the list of existing TCP sessions
                if reversed_tuple in get_tuples:  # check to see if this response is a reply to a request we wrote to the file...
                    http_response_code = http_response_header_results.group(1)
                    http_response_headers = str(http_response_header_results.group(2)).lstrip("\r\n").replace("\"", "%22").split("\n")
                    http_response_header_count = http_response_headers.__len__()
                    http_response_headers_combined = str("\"") # surround the headers with a double-quote so they can be treated as a single value by excel
                    for i in http_response_headers:  # extract and sanitize the interesting response headers, put all headers in httpResponseHeadersCombined
                        if str(i).startswith("Content-Type:"):
                            http_response_content_type = str(i).replace("Content-Type: ", "").replace("\"", "%22").rstrip("\r\n")
                            http_response_headers_combined = str(http_response_headers_combined + "Content-Type: " + http_response_content_type + "\n")
                        elif str(i).startswith("Content-Disposition:"):
                            http_response_content_disposition = str(i).replace("Content-Disposition: ", "").replace("\"", "%22").rstrip("\r\n")
                            http_response_headers_combined = str(http_response_headers_combined + "Content-Disposition: " + http_response_content_disposition + "\n")
                        elif str(i).startswith("Location:"):
                            http_response_location = str(i).replace("Location: ", "").replace("\"", "%22").replace(".", "[.]").replace("http://", "hxxp[:]//").rstrip("\r\n")
                            http_response_headers_combined = str(http_response_headers_combined + "Location: " + http_response_location)
                        else:
                            http_response_headers_combined = str(http_response_headers_combined + str(i).replace("\"", "%22").rstrip("\r\n") + "\n")
                    http_response_headers_combined = str(http_response_headers_combined.rstrip("\n") + "\"")
                    # assign meta variables differently based on response code
                    if http_response_code == 200:
                        if http_response_content_type:
                            response_meta_b = http_response_content_type
                        if http_response_content_disposition:
                            response_meta_c = http_response_content_disposition
                    elif http_response_code in (300, 301, 302):
                        if http_response_location:
                            response_meta_a = http_response_location
                    else:
                        if http_response_location:
                            response_meta_a = http_response_location
                        if http_response_content_type:
                            response_meta_b = http_response_content_type
                        if http_response_content_disposition:
                            response_meta_c = http_response_content_disposition
                    time_stamp = convert_timefromepoch(header.getts()[0])
                    outfile.write(time_stamp + "\t" + str(frame) + "\t" + src_ip + "\t" + tcp_src_port + "\t" + dst_ip + "\t" + tcp_dst_port + "\t" \
                                  + "\t" + str(http_response_header_count) + "\t" + http_response_code \
                                  + "\t" + response_meta_a + "\t" + http_response_headers_combined + "\t" \
                                  + response_meta_b + "\t" + response_meta_c + "\n")
            frame = frame + 1
        except pcapy.PcapError:
            break
end_time = datetime.datetime.now()
time_taken = end_time - start_time
print(str("Script execution time in seconds: " + str(time_taken.seconds)))