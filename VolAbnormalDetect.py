import json
import sys

#Count abnormal processes based on input
def countAbnormalProcesses(processEvaluate,normal):
    global everythingFine
    
    nameList=[]

    for process in processList:
        if process['Name'].lower() == processEvaluate.lower():
            nameList.append(process)
    
    if len(nameList)>normal:
        print('ALERT ',len(nameList),'processes of', processEvaluate)
        everythingFine=False
        for system in nameList:
            print(system)
    

def countAllAbnormalProcesses():
    countAbnormalProcesses('System',1)
    countAbnormalProcesses('services.exe',1)
    countAbnormalProcesses('wininit.exe',1)
    countAbnormalProcesses('lsass.exe',1)
    countAbnormalProcesses('smss.exe',1)


#Check abnormal parent based on input, sometimes the process has a parent but its terminated, so has no parent
def parentAbnormalProcess(processEvaluate,parentName=None):
    global everythingFine

    processPPIDList=[]

    for process in processList:
            if process['Name'].lower() == processEvaluate.lower():
                processPPIDList.append(process['PPID'])
    if not processPPIDList:
        print('Process',processEvaluate,'not found')

    if parentName is None:
        for processPPID in processPPIDList:
            for process in processList:
                if process['PID'] == processPPID:
                    print('ALERT ',process['Name'], 'is parent of',processEvaluate)
                    print(process)
                    everythingFine=False
                    break
    else:
        for processPPID in processPPIDList:
            parentFound=False
            for process in processList:
                if process['PID'] == processPPID and process['Name'].lower()!=parentName.lower():
                    print('ALERT ',process['Name'], 'is parent of',processEvaluate)
                    print(process) 
                    everythingFine=False
                    parentFound=True
                elif process['PID'] == processPPID and process['Name'].lower()==parentName.lower():
                    parentFound=True

            if not parentFound: 
                print('No parent found for',processEvaluate)


def checkAllParentAbnormalProcess():
    parentAbnormalProcess('System')
    parentAbnormalProcess('smss.exe','System')
    parentAbnormalProcess('csrss.exe')
    parentAbnormalProcess('services.exe','wininit.exe')
    parentAbnormalProcess('lsass.exe','wininit.exe')
    parentAbnormalProcess('wininit.exe')
    parentAbnormalProcess('svchost.exe','services.exe')
    parentAbnormalProcess('taskhostw.exe','svchost.exe')
    parentAbnormalProcess('winlogon.exe')




if len(sys.argv) < 2:
    print('JSON input is required')
    print('Usage: python volatility.py <json>')
    sys.exit(1)

pslistJson=sys.argv[1]
with open(pslistJson) as file:
    data = json.load(file)

rows = data['rows']
columns = data['columns']

processList = []
for row in rows:
    row_dict = dict(zip(columns, row))
    processList.append(row_dict)

everythingFine=True

countAllAbnormalProcesses()
checkAllParentAbnormalProcess()

if everythingFine:
    print('No abnormal processes detected. Everything fine')
