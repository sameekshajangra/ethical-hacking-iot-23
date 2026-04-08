import pandas as pd

df = pd.read_csv('iot23_sample.csv', keep_default_na=False)

# Grab a perfect mix for the most visually stunning presentation dashboard
ddos = df[df['detailed_label'] == 'DDoS'].head(100)
mirai = df[df['detailed_label'] == 'Mirai'].head(150)
portscan = df[df['detailed_label'] == 'PartOfAHorizontalPortScan'].head(100)
cnc = df[df['detailed_label'] == 'C&C'].head(50)
benign = df[df['label'] == 'Benign'].head(100)

# Combine and shuffle randomly
test_df = pd.concat([ddos, mirai, portscan, cnc, benign]).sample(frac=1).reset_index(drop=True)

# Remove the answers so the AI has to actually predict it!
test_df = test_df.drop(columns=['label', 'detailed_label'])

test_df.to_csv('presentation_demo_dataset.csv', index=False)
print("Created presentation_demo_dataset.csv with 500 perfectly mixed rows.")
