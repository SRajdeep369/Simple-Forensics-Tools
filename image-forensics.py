from PIL import Image
from PIL.ExifTags import TAGS
import argparse
import glob
import sys
import os


def coordinates(ImageObject):
    info = ImageObject._getexif()
    if not info or not info.get(34853):
        return 0,0
    latDegrees = info[34853][2][0][0]/float(info[34853][2][0][1]) 
    latMinutes = info[34853][2][1][0]/float(info[34853][2][1][1])/60 
    latSeconds = info[34853][2][2][0]/float(info[34853][2][2][1])/3600 
    lonDegrees = info[34853][4][0][0]/float(info[34853][4][0][1]) 
    lonMinutes = info[34853][4][1][0]/float(info[34853][4][1][1])/60 
    lonSeconds = info[34853][4][2][0]/float(info[34853][4][2][1])/3600 
    
    
    latitude = latDegrees + latMinutes + latSeconds
    if info[34853][1] == 'S':
        latitude*= -1
    longitude = lonDegrees + lonMinutes + lonSeconds 
    if info[34853][3] == 'W':
        longitude*=-1
    return longitude,latitude


def print_exif(ImageObject):
    exifdict=ImageObject._getexif()
    if exifdict:
       for name,data in list(exifdict.items()):
           tagname="unknown-tag"
           if name in TAGS:
               tagname=TAGS[name]
           print("TAG:%s (%s) is assigned %s" % (name,tagname,data)) 
    return


parser=argparse.ArgumentParser()
parser.add_argument('-d','--display',action='store_true',required=False,help='Display the image')
parser.add_argument('-m','--maps',action='store_true',required=False,help='Print google maps links')
parser.add_argument('-e','--exif',action='store_true',required=False,help='Display the exif data')
parser.add_argument('-p','--pause',action='store_true',required=False,help='Pause after each image')
parser.add_argument('image_directory', help='A file path containing images to process')
args=parser.parse_args()

listoffiles = glob.glob(args.image_directory + "*.jpg")
if len(listoffiles)==0:
   print("No Matching files found matching %s*.jpg" % (args.image_directory))
   sys.exit(3)

for file in listoffiles:
    print("[*] Processing file %s " % (file))
    try:
        imageobject = Image.open(file)
    except Exception as e:
        print("An exception occured displaying the image." + str(e))
        continue
    if args.exif:
        print_exif(imageobject)
    if args.maps:
        lon, lat = coordinates(imageobject)
        if lon and lat:
            print("http://maps.google.com/maps?q=%.9f,%.9f&z=15" % (lat, lon))
    if args.display: 
        newimage = imageobject.resize((200, 200), Image.ANTIALIAS)
        newimage.show()
    if args.pause:
        x = input("Press enter to continue")

