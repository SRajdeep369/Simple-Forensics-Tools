import etw
import psutil

def checker(x):
    # print(x)
    rPPID=int(x[1]['EventHeader']['ProcessId'])
    oPPID=int(x[1]['ParentProcessID'])
    PID=int(x[1]['ProcessID'])

    if rPPID==oPPID:
        # print("Not Spoofed.")
        pass
    else:
        print("Spoofed Process Observed!")
        PName="Not Recorded/Process Ended!"
        fPPName="Not Recorded/Process Ended!"
        rPPN="Not Recorded/Process Ended!"
        for process in psutil.process_iter():
            if process.pid == PID:
                PName = process.name()
            elif process.pid == oPPID:
                fPPName = process.name()
            elif process.pid == rPPID:
                rPPN = process.name()
        print("Alerted Process Name:"+PName+"\nSpoofed Parent Name:"+fPPName+"\nReal Parent Name:"+rPPN)
        print("Raw Data:\n"+str(x))


def jobRunner():
    
    providers = [etw.ProviderInfo('Microsoft-Windows-Kernel-Process', etw.GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"))]
    
    # create instance of ETW class
    job = etw.ETW(providers=providers, event_callback=lambda x: checker(x), task_name_filters="PROCESSSTART")
    
    # start capture
    job.start()

    try:
        while True:
            pass
    except(KeyboardInterrupt):
        job.stop()

if __name__ == '__main__':
    jobRunner()
