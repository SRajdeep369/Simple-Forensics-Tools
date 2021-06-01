import requests
import csv
import time

url = 'https://www.virustotal.com/vtapi/v2/file/report'

f=open('result.csv','w+')
f.write("MD5,sha256,Total Scans,Total Detections,Symantec Detection,Symantec Malware Name\n")


with open('sample_hashes.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
            nodata=0
            print("Checking For:"+row[0])
            line_count += 1
            if(line_count%4==1 and line_count!=1):
                print("Called Sleep")
                time.sleep(60)
            params = {'apikey': '', 'resource': row[0]}
            # print(params)
            response = requests.get(url, params=params)
            md5s=row[0]
            data = response.json()

            try:

                print("SHA256:"+data['sha256'])
                print("Total Scans:"+str(data['total'])+" | Positives:"+str(data['positives']))
                sha256=data['sha256']
                total_scan=str(data['total'])
                total_pos=str(data['positives'])
            except:
                print("No Data")
                nodata=1
                sha256="NA"
                total_scan="NA"
                total_pos="NA"
                symantec_detection="NA"
                symantec_name="NA"
            if(nodata==0):
                try:
                    print("Symantec Detection:"+str(data['scans']['Symantec']['detected']))
                    print("Symantec Malware Name:"+str(data['scans']['Symantec']['result']))
                    symantec_detection=str(data['scans']['Symantec']['detected'])
                    symantec_name=str(data['scans']['Symantec']['result'])
                
                except:
                    print("No Symantec Response")
                    symantec_detection="False"
                    symantec_name="NA"
            f.write(md5s+","+sha256+","+total_scan+","+total_pos+","+symantec_detection+","+symantec_name+"\n")
            
    print(f'Processed {line_count} hashes.')
    f.close()




# data = response.json()

# print("SHA256:"+data['sha256'])
# print("Total Scans:"+str(data['total'])+" | Positives:"+str(data['positives']))
# print("Symantec Detection:"+str(data['scans']['Symantec']['detected']))
# print("Symantec Malware Name:"+str(data['scans']['Symantec']['result']))
# print(data)