import matplotlib.pyplot as plt
import numpy as np

plt.figure(figsize=(12, 8))

x = ['Cache', 'LB', 'HH', 'NC', 'All-mixed']
plt.yticks([0, 500, 1000, 1500, 2000, 2500, 3000])

plt.xticks(fontsize=31)
plt.yticks(fontsize=40)

a = [2107, 2815, 1097, 569, 1351]
b = [1793, 1408, 639, 319, 1066]
c = [1407, 703, 319, 159, 609]
d = [352, 814, 0, 154, 600]
e = [35, 41, 0, 10, 77]

# x-axis coordinates, size=5, returns [0, 1, 2, 3, 4]
size = 5
xx = np.arange(size)
plt.xlim()

plt.ylim(bottom=0, top=3000)

# Width of each type of bar
width = 0.18

# Draw the bar chart

pic1=plt.bar(xx - 2*width, a, width=width, label="a", color='mistyrose', zorder=0, hatch='/')
plt.bar(xx - 2*width, a, width=width, label="a", edgecolor='black', color='none', lw=1, zorder = 1)

pic2=plt.bar(xx - 1*width, b, width=width, label="b", color='#ED3333', zorder=0, hatch='\\')
plt.bar(xx - 1*width, b, width=width, label="b", edgecolor='black', color='none', lw=1., zorder = 1)

pic3=plt.bar(xx, c, width=width, label="c", color='#F1908C', zorder=0, hatch='x')
# pic3=plt.bar(xx + 1*width, c, width=width, label="c", edgecolor='#F1908C', hatch='/////', color='none', lw=1., zorder = 0)
plt.bar(xx, c, width=width, label="c", edgecolor='black', color='none', lw=1., zorder = 1)

pic4=plt.bar(xx + 1*width, d, width=width, label="d", color='#2F90B9', zorder = 0, hatch='o')
plt.bar(xx + 1*width, d, width=width, label="d", edgecolor='black', color='none', lw=1., zorder = 1)

pic5=plt.bar(xx + 2*width, e, width=width, label="e", color='skyblue', zorder = 0, hatch='.')
plt.bar(xx + 2*width, e, width=width, label="e", edgecolor='black', color='none', lw=1., zorder = 1)



# Set the x-axis tick labels to the values in the x list
plt.xticks(xx, x)

# Add labels to the x and y axes
plt.xlabel('Workload', fontsize=40, fontweight='bold')
plt.ylabel('Program Capacity', fontsize=40, fontweight='bold')

# Add horizontal and vertical grid lines
plt.grid(axis='both', linestyle='--', color='gray', alpha=0.7)


# Select the items to be displayed
handles = [pic1, pic2, pic3, pic4, pic5]
labels = ['Baseline', '2048B', '4096B', '16 Cases', '256 Cases']

plt.legend(handles=handles, labels=labels, edgecolor="#000000", prop={'size': 24}, loc='upper right')



# Display the bar chart
# plt.show()

plt.savefig('../figure/draw_ProgramCapacity.png',bbox_inches='tight')
plt.savefig('../figure/draw_ProgramCapacity.svg',bbox_inches='tight')
