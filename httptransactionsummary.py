'''
parse-httpheaders.py is intended to take a .pcap and output a .TSV for opening in Excel

This script uses the pcapy and impacket libraries.

https://github.com/CoreSecurity/pcapy
https://github.com/CoreSecurity/impacket

Author: Harold Ogden (haroldogden@gmail.com)
'''
import re
import Tkinter
import tkFileDialog
import datetime
import time
try:
    import pcapy
    from impacket.ImpactPacket import *
    from impacket.ImpactDecoder import *
except:
    print("pcapy or impacket not found - check links in script comments.")
    exit()
root = Tkinter.Tk()
root.withdraw()
try:
    maxHeaderCountInput = input("Maximum desired headers in HTTP requests. Leave blank for unlimited: ")
    maxHeaderCountInput = int(maxHeaderCountInput)
except:
    maxHeaderCountInput = None
    print("Null or invalid max header count - header count set to unlimited.")
# note - all http responses will be shown if a request to the 4 tuple (src ip, dst ip, src port, dst port)
# has been seen previously


def convert_timefromepoch(epochTimestamp): return time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(epochTimestamp))

print("Please select a .pcap file...")
pcapFilePath = tkFileDialog.askopenfilename()
print("Please choose a location for the output .tsv")
outputFilePath = tkFileDialog.asksaveasfilename()
if not pcapFilePath:
    print("Please select a file.")
    exit()
try:
    reader = pcapy.open_offline(pcapFilePath)
except:
    print("Failed to read pcapFilePath - please select a valid .pcap file")
    exit()
startTime = datetime.datetime.now()
getTuples = str("") # this will be a list of src_ip:src_port>dst_ip:dst_port that we check responses against before we display them
# here come the regex!
httpRequestPattern = re.compile(r'(?s).{54,94}(GET|POST|PUT|HEAD) (([^/]*)\S*(/\S*)) HTTP/1\.[01]((?:(?:(?:\r\n)|\n)[^:]*: [^\r\n]+)*)(?:(?:\r\n)|\n){2}')  # up to max tcp header
httpResponsePattern = re.compile(r'(?s).{54,94}HTTP/1\.[01] (\d+)[^\r\n]*((?:(?:(?:\r\n)|\n)[^:]*: [^\r\n]+)*)(?:(?:\r\n)|\n){2}')  # up to max header
# ok, no more regex
frame = 1
decoder = EthDecoder()
with open(outputFilePath, 'w') as outFile:
    #  output the headerrs to the TSV file
    outFile.write("timeStamp\tframe\tsource_address\tsource_port\tdestination_address\tdestination_port\thost\theadercount\tmethod/code\turl/responsemeta\theaders\tuser-agent/content-type\treferer/content-disposition\n")
    while True:
        httpRequestHeaderResults = None
        httpResponseHeaderResults = None
        try:
            (header, payload) = reader.next()
            httpRequestHeaderResults = re.match(httpRequestPattern, payload)  # re.match is used to deliberately search only once at the beginning of the string
            if not httpRequestHeaderResults:
                httpResponseHeaderResults = re.match(httpResponsePattern, payload)
            if httpRequestHeaderResults:
                packet = decoder.decode(payload)
                l2 = packet.child()
                if isinstance(l2, IP):
                    l3 = l2.child()
                    if isinstance(l3, TCP):
                        src_ip = str(l2.get_ip_src())
                        dst_ip = str(l2.get_ip_dst())
                        tcp_src_port = str(l3.get_th_sport())
                        tcp_dst_port = str(l3.get_th_dport())
                # grab data out of the regex results groups, then go through the headers looking for goodies
                httpRequestMethod = httpRequestHeaderResults.group(1)
                httpRequestURL = httpRequestHeaderResults.group(2)
                httpRequestFile = httpRequestHeaderResults.group(4)
                # the http headers are \r\n delimited by RFC, but \n is also allowed. Split them into their own list:
                httpRequestHeaders = str(httpRequestHeaderResults.group(5)).lstrip("\r\n").replace("\"", "%22").split("\n")
                httpRequestHeaderCount = httpRequestHeaders.__len__()  # and once split, get a count of the headers
                if maxHeaderCountInput:  # if the user provided an int, this code block is used. The only difference between this and the "else"...
                                         # is that this block checks the count of headers prior to writing to the file and adding to the four-tuple
                                         # variable containing the IPs/ports of the HTTP request
                    if httpRequestHeaderCount <= maxHeaderCountInput:
                        # prepare empty strings in case they don't get filled up by looking at the headers
                        httpRequestHost = str("")
                        httpUserAgent = str("")
                        httpRequestReferer = str("")
                        httpRequestHeadersCombined = str("\"") # surround the headers with a double-quote so they can be treated as a single value by excel
                        for i in httpRequestHeaders: #  sanitize headers, put special ones into their own variable, put all into a httpResponseHeadersCombined variable
                            if str(i).startswith("Host:"):
                                httpRequestHost = i.replace("Host: ", "").replace(".", "[.]").rstrip("\r\n")  # don't need to be clickin malware urls
                                httpRequestHeadersCombined = str(httpRequestHeadersCombined + str("Host: " + httpRequestHost) + "\n")
                            elif str(i).startswith("User-Agent:"):
                                httpUserAgent = i.replace("User-Agent: ", "").rstrip("\r\n")
                                httpRequestHeadersCombined = str(httpRequestHeadersCombined + str("User-Agent: " + httpUserAgent) + "\n")
                            elif str(i).startswith("Referer:"):
                                httpRequestReferer = i.replace("Referer: ", "").replace(".", "[.]").replace("http://", "hxxp[:]//").rstrip("\r\n")
                                httpRequestHeadersCombined = str(httpRequestHeadersCombined + str("Referer: " + httpRequestReferer) + "\n")
                            else:
                                httpRequestHeadersCombined = str(httpRequestHeadersCombined + str(i).rstrip("\r\n") + "\n")
                        httpRequestHeadersCombined = str(httpRequestHeadersCombined.rstrip("\n") + "\"") # remove the final newline...
                        #  and add a double-quote to make the TSV treat all headers as a single value.
                        getTuples = (getTuples + src_ip + ":" + tcp_src_port + ">" + dst_ip + ":" + tcp_dst_port)  # add this request's src/dst ip/ports to a list
                        # output to the .TSV - all done with the HTTP request!
                        timeStamp = convert_timefromepoch(header.getts()[0])
                        outFile.write(timeStamp + "\t" + str(frame) + "\t" + src_ip + "\t" + tcp_src_port + "\t" + dst_ip + "\t" + tcp_dst_port + "\t"\
                                                 + httpRequestHost + "\t" + str(httpRequestHeaderCount) + "\t" + httpRequestMethod\
                                                 + "\t" + httpRequestURL + "\t" + httpRequestHeadersCombined + "\t"\
                                                 + httpUserAgent + "\t" + httpRequestReferer + "\n")
                else:
                    # prepare empty strings in case they don't get filled up by looking at the headers
                    httpRequestHost = str("")
                    httpUserAgent = str("")
                    httpRequestReferer = str("")
                    httpRequestHeadersCombined = str("\"") # surround the headers with a double-quote so they can be treated as a single value by excel
                    for i in httpRequestHeaders: #  sanitize headers, put special ones into their own variable, put all into a httpResponseHeadersCombined variable
                        if str(i).startswith("Host:"):
                            httpRequestHost = i.replace("Host: ", "").replace(".", "[.]").rstrip("\r\n")  # don't need to be clickin malware urls
                            httpRequestHeadersCombined = str(httpRequestHeadersCombined + str("Host: " + httpRequestHost) + "\n")
                        elif str(i).startswith("User-Agent:"):
                            httpUserAgent = i.replace("User-Agent: ", "").rstrip("\r\n")
                            httpRequestHeadersCombined = str(httpRequestHeadersCombined + str("User-Agent: " + httpUserAgent) + "\n")
                        elif str(i).startswith("Referer:"):
                            httpRequestReferer = i.replace("Referer: ", "").replace(".", "[.]").replace("http://", "hxxp[:]//").rstrip("\r\n")
                            httpRequestHeadersCombined = str(httpRequestHeadersCombined + str("Referer: " + httpRequestReferer) + "\n")
                        else:
                            httpRequestHeadersCombined = str(httpRequestHeadersCombined + str(i).rstrip("\r\n") + "\n")
                    httpRequestHeadersCombined = str(httpRequestHeadersCombined.rstrip("\n") + "\"") # remove the final newline...
                    #  and add a double-quote to make the TSV treat all headers as a single value.
                    getTuples = (getTuples + src_ip + ":" + tcp_src_port + ">" + dst_ip + ":" + tcp_dst_port)
                    timeStamp = convert_timefromepoch(header.getts()[0])
                    outFile.write(timeStamp + "\t" + str(frame) + "\t" + src_ip + "\t" + tcp_src_port + "\t" + dst_ip + "\t" + tcp_dst_port + "\t"\
                                             + httpRequestHost + "\t" + str(httpRequestHeaderCount) + "\t" + httpRequestMethod\
                                             + "\t" + httpRequestURL + "\t" + httpRequestHeadersCombined + "\t"\
                                             + httpUserAgent + "\t" + httpRequestReferer + "\n")
            elif httpResponseHeaderResults:  # http response was found!
                responseMetaA = ""  # clearing them variables. Some need to be strings so if they get written to a file, they end up as nothing between the two tabs...
                responseMetaB = ""
                responseMetaC = ""
                httpResponseContentDisposition = None  # and these are set to "None" so we can check if they exist
                httpResponseContentType = None
                httpResponseLocation = None
                packet = decoder.decode(payload)
                l2 = packet.child()
                if isinstance(l2, IP):
                    l3 = l2.child()
                    if isinstance(l3, TCP):
                        src_ip = str(l2.get_ip_src())
                        dst_ip = str(l2.get_ip_dst())
                        tcp_src_port = str(l3.get_th_sport())
                        tcp_dst_port = str(l3.get_th_dport())
                reversedTuple = (dst_ip + ":" + tcp_dst_port + ">" + src_ip + ":" + tcp_src_port)  # reverse this packet's IPs and ports so we
                                                                                                   # can check the list of existing TCP sessions
                if reversedTuple in getTuples:  # check to see if this response is a reply to a request we wrote to the file...
                    httpResponseCode = httpResponseHeaderResults.group(1)
                    httpResponseHeaders = str(httpResponseHeaderResults.group(2)).lstrip("\r\n").replace("\"", "%22").split("\n")
                    httpResponseHeaderCount = httpResponseHeaders.__len__()
                    httpResponseHeadersCombined = str("\"") # surround the headers with a double-quote so they can be treated as a single value by excel
                    for i in httpResponseHeaders:  # extract and sanitize the interesting response headers, put all headers in httpResponseHeadersCombined
                        if str(i).startswith("Content-Type:"):
                            httpResponseContentType = str(i).replace("Content-Type: ", "").replace("\"", "%22").rstrip("\r\n")
                            httpResponseHeadersCombined = str(httpResponseHeadersCombined + "Content-Type: " + httpResponseContentType + "\n")
                        elif str(i).startswith("Content-Disposition:"):
                            httpResponseContentDisposition = str(i).replace("Content-Disposition: ", "").replace("\"", "%22").rstrip("\r\n")
                            httpResponseHeadersCombined = str(httpResponseHeadersCombined + "Content-Disposition: " + httpResponseContentDisposition + "\n")
                        elif str(i).startswith("Location:"):
                            httpResponseLocation = str(i).replace("Location: ", "").replace("\"", "%22").replace(".", "[.]").replace("http://", "hxxp[:]//").rstrip("\r\n")
                            httpResponseHeadersCombined = str(httpResponseHeadersCombined + "Location: " + httpResponseLocation)
                        else:
                            httpResponseHeadersCombined = str(httpResponseHeadersCombined + str(i).replace("\"", "%22").rstrip("\r\n") + "\n")
                    httpResponseHeadersCombined = str(httpResponseHeadersCombined.rstrip("\n") + "\"")
                    # assign meta variables differently based on response code
                    if httpResponseCode == 200:
                        if httpResponseContentType:
                            responseMetaB = httpResponseContentType
                        if httpResponseContentDisposition:
                            responseMetaC = httpResponseContentDisposition
                    elif httpResponseCode in (300, 301, 302):
                        if httpResponseLocation:
                            responseMetaA = httpResponseLocation
                    else:
                        if httpResponseLocation:
                            responseMetaA = httpResponseLocation
                        if httpResponseContentType:
                            responseMetaB = httpResponseContentType
                        if httpResponseContentDisposition:
                            responseMetaC = httpResponseContentDisposition
                    timeStamp = convert_timefromepoch(header.getts()[0])
                    outFile.write(timeStamp + "\t" + str(frame) + "\t" + src_ip + "\t" + tcp_src_port + "\t" + dst_ip + "\t" + tcp_dst_port + "\t"\
                                             + "\t" + str(httpResponseHeaderCount) + "\t" + httpResponseCode\
                                             + "\t" + responseMetaA + "\t" + httpResponseHeadersCombined + "\t"\
                                             + responseMetaB + "\t" + responseMetaC + "\n")
            frame = frame + 1
        except pcapy.PcapError:
            break
endTime = datetime.datetime.now()
timeTaken = endTime - startTime
print(str("Script execution time in seconds: " + str(timeTaken.seconds)))