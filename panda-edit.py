import pandas as pd
f=pd.read_csv("log_1.csv")
keep_col = ['Receive Time','Source Zone','Inbound Interface','Start Time']
new_f = f[keep_col]
new_f.to_csv("log_1_2.csv", index=False)
