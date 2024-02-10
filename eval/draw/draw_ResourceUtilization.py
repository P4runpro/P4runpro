import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib
matplotlib.use('Agg')
import pandas as pd

epoch_time = 3000
# Store the average memory_utilization and table_entry_utilization for each epoch of each experiment scheme
average_memory_utilizations = []
average_table_entry_utilizations = []

# Iterate over each experiment scheme
for scheme_id in range(4):
    print(scheme_id)
    scheme_directory = "../data/config10/scheme{}/".format(scheme_id)

    # Store memory_utilization and table_entry_utilization for each epoch of the current experiment scheme
    memory_utilizations_per_scheme = {epoch: [] for epoch in range(epoch_time)}
    table_entry_utilizations_per_scheme = {epoch: [] for epoch in range(epoch_time)}

    # Iterate over each experiment
    for experiment_id in range(1):
        experiment_directory = os.path.join(scheme_directory, str(experiment_id))

        # Check if the folder exists
        if os.path.exists(experiment_directory):
            # Iterate over each epoch
            for epoch in range(epoch_time):
                file_path = os.path.join(experiment_directory, "output.json")

                # Check if the file exists
                if os.path.exists(file_path):
                    with open(file_path, 'r') as file:
                        data = json.load(file)

                        # Get memory_utilization and table_entry_utilization for the current epoch
                        if str(epoch) in data:
                            memory_utilization = data[str(epoch)]['memory_utilizaiton']
                            table_entry_utilization = data[str(epoch)]['table_entry_utilization']
                            t1 = memory_utilization
                            t2 = table_entry_utilization

                            memory_utilizations_per_scheme[epoch].append(memory_utilization)
                            table_entry_utilizations_per_scheme[epoch].append(table_entry_utilization)
                        else:
                            memory_utilizations_per_scheme[epoch].append(t1)
                            table_entry_utilizations_per_scheme[epoch].append(t2)

    # Calculate the average memory_utilization and table_entry_utilization for each epoch and store them
    average_memory_utilizations_per_scheme = [np.mean(values) for values in memory_utilizations_per_scheme.values()]
    average_table_entry_utilizations_per_scheme = [np.mean(values) for values in table_entry_utilizations_per_scheme.values()]

    average_memory_utilizations.append(average_memory_utilizations_per_scheme)
    average_table_entry_utilizations.append(average_table_entry_utilizations_per_scheme)


# Plot a line chart
fig, ax = plt.subplots(figsize=(12, 8))

memory_utilization_labels = ['Cache-Mem', 'LB-Mem','HH-Mem','Mixed-Mem']
table_entry_utilization_labels = ['Cache-Entry', 'LB-Entry','HH-Entry','Mixed-Entry']

colors = ['tab:blue', 'tab:orange', 'tab:green', 'tab:red']

for i in range(4):
    ax.plot(range(epoch_time), average_memory_utilizations[i], label=memory_utilization_labels[i], linestyle='solid', color=colors[i],linewidth=4.0)
for i in range(4):
    ax.plot(range(epoch_time), average_table_entry_utilizations[i], label=table_entry_utilization_labels[i], linestyle='dashdot', color=colors[i],linewidth=4.0)

ax.set_xlabel('Epoch', fontsize=40, fontweight='bold')
ax.set_ylabel('Utilization', fontsize=40, fontweight='bold')
ax.legend(loc='lower left', ncol=2, fontsize=24, columnspacing=0.5)
# bbox_to_anchor=(0.5, 1.15)
# Set the font size of the axis labels
ax.tick_params(axis='both', labelsize=40)

# Add horizontal and vertical grid lines
ax.grid(axis='both', linestyle='--', color='gray', alpha=0.7)

ax.set_xlim(left=0,right=epoch_time)
# Set the bottom of the y-axis to '0'
ax.set_ylim(bottom=0,top=1)

plt.savefig('../figure/draw_ResourceUtilization.png',bbox_inches='tight')
plt.savefig('../figure/draw_ResourceUtilization.svg',bbox_inches='tight')
