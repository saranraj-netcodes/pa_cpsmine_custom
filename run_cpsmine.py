import subprocess
import csv
import cpsmine

for i in range (1, 63, 1):
    file_name = "log_3_"+str(i)+".csv"
    print(file_name)
    subprocess.run(["./cpsmine.py", "-z", "untrust", "-p", "all", "-f", str(file_name)])
