import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

directory = "../data/config5/scheme0"

# Traverse the files in the directory
max_key = 0
max_repeat = 0
for i in range(10):
    file_path = os.path.join(directory, str(i), "output.json")
    
    # Check whether the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Gets the maximum key of the current file and adds it to the list
            key = max(map(int, data.keys()), default=0)
            if(key > max_key):
                max_key = key
                max_repeat = i



# Store the average memory utilization per segment
average_memory_utilization_per_segment = []

# Defines the size of the segment
segment_size = 100

# Calculate the number of segments
num_segments = (max_key + 1) // segment_size

for segment in range(num_segments):
    print(segment)
    # Store memory utilization for each stage of the current segment
    memory_utilization_per_stage = np.zeros(22)
    
    # Calculate the start and end epochs of the current segment
    start_epoch = segment * segment_size
    end_epoch = min((segment + 1) * segment_size, max_key + 1)
    
    file_path = os.path.join(directory, str(max_repeat), "output.json")
    # Check whether the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            # Traverse each epoch in the current segment
            for epoch in range(start_epoch, end_epoch):
                if str(epoch) in data:
                    memory_utilization = data[str(epoch)]['table_entry_utilization_per_stage']
                    memory_utilization = np.array(eval(memory_utilization)) 
    average_memory_utilization_per_segment.append(memory_utilization)


# Convert to numpy array
heatmap_data = np.array(average_memory_utilization_per_segment)
heatmap_data = heatmap_data.transpose()
print(heatmap_data)

# Mapping heat map
plt.figure(figsize=(12, 8))

heatmap = plt.imshow(heatmap_data, cmap='YlOrRd', aspect='auto', interpolation='none', vmin=0, vmax=1)

cbar_kws = {"label": 'Entry Utilization', "ticks": [0, 0.2, 0.4, 0.6, 0.8, 1]}
cbar = plt.colorbar(heatmap, **cbar_kws)

cbar.ax.set_ylabel('Entry Utilization', fontsize=40, fontweight='bold')

cbar.ax.tick_params(labelsize=40)

# Flip vertical axis
plt.gca().invert_yaxis()

plt.xlabel('Epoch Segment', fontsize=40, fontweight='bold')
plt.ylabel('RPB', fontsize=40, fontweight='bold')

selected_ticks3 = [0, 2, 4, 6, 8, 10, 12]
selected_ticks4 = [0, 1, 2, 3, 4, 5, 6, 7]
plt.xticks(selected_ticks3, [str(x+1) for x in selected_ticks3], fontsize=40)

selected_ticks = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
plt.yticks(selected_ticks, [str(x+1) for x in selected_ticks], fontsize=40)

plt.savefig('../figure/draw_AlternativeOptimizationChoice_HeatMap_Tableconfig5.png',bbox_inches='tight')
plt.savefig('../figure/draw_AlternativeOptimizationChoice_HeatMap_Tableconfig5.svg',bbox_inches='tight')
