# import pandas as pd
# from operator import itemgetter
import csv
import matplotlib.pyplot as plt
import ipaddress
from matplotlib.ticker import FuncFormatter
import numpy as np
import sys

def autolabel(rects, xpos='center'):
    """
    Attach a text label above each bar in *rects*, displaying its height.

    *xpos* indicates which side to place the text w.r.t. the center of
    the bar. It can be one of the following {'center', 'right', 'left'}.
    """

    xpos = xpos.lower()  # normalize the case of the parameter
    ha = {'center': 'center', 'right': 'left', 'left': 'right'}
    offset = {'center': 0.5, 'right': 0.57, 'left': 0.43}  # x_txt = x + w*off

    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()*offset[xpos], 1.01*height,
                '{}'.format(height), ha=ha[xpos], va='bottom')

path = sys.argv[1]
name = path.split('\\')[5]
name = name.split('.')[0]


with open(path, 'r') as f:
  reader = csv.reader(f)
  row = list(reader)


high_vuln = 0
medium_vuln = 0
max_high_vuln = 0
cve_number = 1
number_of_ips = 1
koeficient_poctu_ip = 0
pocet_sekani = 0
cast_pole_predchozi = 0
cast_pole = 0


plotter_highest_cve = list()
plotter_most_cves = list()
plotter_medium_cves = list()
plotter_high_cves = list()

# print(len(row) + 1)
for i in range(1,len(row) + 1):
	
	if (i == len(row) - 1):
		# print("IP:", row[i][0], ", high vulnerabilities:", high_vuln, ", medium vulnerabilities:", medium_vuln, ", maximal vulnerability score:", max_high_vuln)
		# print(i)

		plotter_highest_cve.append([row[i][0], max_high_vuln])
		plotter_most_cves.append([row[i][0], cve_number])
		plotter_medium_cves.append([row[i][0], medium_vuln])
		plotter_high_cves.append([row[i][0], high_vuln])

		break

	if (row[i + 1][0] != row[i][0]):
		# print("IP:", row[i][0], ", high vulnerabilities:", high_vuln, ", medium vulnerabilities:", medium_vuln, ", maximal vulnerability score:", max_high_vuln)
		# print(i)

		plotter_highest_cve.append([row[i][0], max_high_vuln])
		plotter_most_cves.append([row[i][0], cve_number])
		plotter_medium_cves.append([row[i][0], medium_vuln])
		plotter_high_cves.append([row[i][0], high_vuln])

		high_vuln = 0
		medium_vuln = 0
		max_high_vuln = 0
		cve_number = 1
		number_of_ips += 1
	else:
		if (float(row[i][2]) >= 7):
			high_vuln += 1
		if (float(row[i][2]) >= 4 and float(row[i][2]) < 7):
			medium_vuln += 1
		if (float(row[i][2]) > max_high_vuln):
			max_high_vuln = float(row[i][2])
		cve_number += 1

print(number_of_ips)
#print(plotter_highest_cve)
#print(plotter_most_cves)
#print(plotter_medium_cves)
#print(plotter_high_cves)

#############################################################################################################
# _____________________________________________ ROZSEKANI LISTU ___________________________________________ #
#############################################################################################################


'''
if(number_of_ips % 35 >= 10):
	pocet_sekani = (number_of_ips // 35) + 1
	koeficient_poctu_ip = 35
elif(number_of_ips % 35 == 0):
	pocet_sekani = number_of_ips // 35
	koeficient_poctu_ip = 35
else:
	pocet_sekani = (number_of_ips // 10) + 1
	koeficient_poctu_ip = 10
'''
if(number_of_ips % 35 == 0):
	pocet_sekani = number_of_ips // 35
	koeficient_poctu_ip = 35
else:
	pocet_sekani = (number_of_ips // 35) + 1
	koeficient_poctu_ip = 35

for a in range(pocet_sekani):
	cast_pole_predchozi = cast_pole
	cast_pole = koeficient_poctu_ip * (a + 1)

	print(cast_pole)

	plotter_highest_cve = sorted(plotter_highest_cve, key=lambda x: (x[1], x[0]), reverse=True)
	plotter_most_cves = sorted(plotter_most_cves, key=lambda x: (x[1], x[0]), reverse=True)
	plotter_medium_cves = sorted(plotter_medium_cves, key=lambda x: (int(x[0].split('.')[3]), x[1]))
	plotter_high_cves = sorted(plotter_high_cves, key=lambda x: (int(x[0].split('.')[3]), x[1]))


	plotter_highest_cve_sorted = plotter_highest_cve[cast_pole_predchozi:cast_pole]
	plotter_most_cves_sorted = plotter_most_cves[cast_pole_predchozi:cast_pole]
	plotter_medium_cves_sorted = plotter_medium_cves[cast_pole_predchozi:cast_pole]
	plotter_high_cves_sorted = plotter_high_cves[cast_pole_predchozi:cast_pole]




######################################################################################################
# _____________________________________________ PLOTTING ___________________________________________ #
######################################################################################################


	
	name_of_file = plotter_medium_cves_sorted[0][0].replace('.', '_') + '_' + plotter_medium_cves_sorted[len(plotter_medium_cves_sorted) - 1][0].replace('.', '_')


	##########################################################################################################
	# _____________________________________________ NEJVYSSI CVE ___________________________________________ #
	##########################################################################################################

	plot_x = list()
	plot_y = list()
	ticks = list()
	for x, y in plotter_highest_cve_sorted:
		#plot_x.append(int(ipaddress.ip_address(x)))
		plot_x.append(x)
		#ticks.append(x.split('.')[3])
		ticks.append(x)
		plot_y.append(y)

	# print(plotter_high_cves_sorted)
	# print(plotter_medium_cves_sorted)
	# print(plotter_most_cves_sorted)
	# print(plotter_highest_cve_sorted)

	# print(plot_x)
	# print(ticks)
	# print(plot_y)



	fig = plt.figure(figsize=(19.2, 10.8), dpi=100)
	ax = plt.subplot(111)

	# ax.bar(plot_x, plot_y, color="black", align='center')
	rect = ax.bar(plot_x, plot_y, color="SkyBlue", align='center', width= 0.5)

	ax.axis([-1, len(ticks) + 1, 0, max(plot_y) + 1])
	plt.xticks(plot_x, ticks, horizontalalignment='right', rotation=40)
	plt.xlabel('Hosti')
	plt.ylabel('CVE - nejvyssi hodnoty')
	plt.title('Hosti s nejvyssim skore CVE - sestupne')
	plt.tight_layout()

	autolabel(rect, "center")
	fig.savefig(name_of_file + '_highest_cve.pdf', bbox_inches='tight', format='pdf')
	fig.savefig(name_of_file + '_highest_cve.png', bbox_inches='tight', format='png')
	

	#########################################################################################################
	# _____________________________________________ NEJVICE CVE ___________________________________________ #
	#########################################################################################################

	plot_x = list()
	plot_y = list()
	ticks = list()
	for x, y in plotter_most_cves_sorted:
		#plot_x.append(int(ipaddress.ip_address(x)))
		plot_x.append(x)
		#ticks.append(x.split('.')[3])
		ticks.append(x)
		plot_y.append(y)

	# print(plotter_high_cves_sorted)
	# print(plotter_medium_cves_sorted)
	# print(plotter_most_cves_sorted)
	# print(plotter_highest_cve_sorted)

	# print(plot_x)
	# print(ticks)
	# print(plot_y)

	fig = plt.figure(figsize=(19.2, 10.8), dpi=100)
	ax = plt.subplot(111)

	# ax.bar(plot_x, plot_y, color="black", align='center')
	rect = ax.bar(plot_x, plot_y, color="SkyBlue", align='center', width= 0.5)

	ax.axis([-1, len(ticks) + 1, 0, max(plot_y) + 1])
	plt.xticks(plot_x, ticks, horizontalalignment='right', rotation=40)
	plt.xlabel('Hosti')
	plt.ylabel('CVE - pocet')
	plt.title('Hosti s nejvyssim poctem CVE - sestupne')
	plt.tight_layout()

	autolabel(rect, "center")
	fig.savefig(name_of_file + '_most_cves.pdf', bbox_inches='tight', format='pdf')
	fig.savefig(name_of_file + '_most_cves.png', bbox_inches='tight', format='png')
	
	#########################################################################################################
	# _____________________________________________ MEDIUM/HIGH CVE ________________________________________#
	#########################################################################################################

	plot_x_1 = list()
	plot_x_2 = list()
	plot_y_1 = list()
	plot_y_2 = list()
	ticks = list()
	width = 0.35

	for x, y in plotter_high_cves_sorted:
		#plot_x.append(int(ipaddress.ip_address(x)))
		plot_x_1.append(x)
		#ticks.append(x.split('.')[3])
		ticks.append(x)
		plot_y_1.append(y)

	for x, y in plotter_medium_cves_sorted:
		#plot_x.append(int(ipaddress.ip_address(x)))
		plot_x_2.append(x)
		plot_y_2.append(y)


	fig, ax = plt.subplots(figsize=(19.2, 10.8), dpi=100)
	ind = np.arange(len(plot_x_1))

	# ax.bar(plot_x, plot_y, color="black", align='center')
	rects1 = ax.bar(ind - width/2, plot_y_1, width=width, color="IndianRed", label='High CVEs')
	rects2 = ax.bar(ind + width/2, plot_y_2, width=width, color="SkyBlue", label='Medium CVEs')

	#ax.axis([-1, len(plot_x_1) + 1, 0, max(plot_y_1 + plot_y_2) + 1])
	ax.set_xticks(ind)
	ax.set_xticklabels(ticks, horizontalalignment='right', rotation=40)
	ax.legend()
	plt.xlabel('Hosti')
	plt.ylabel('CVE - pocet')
	plt.title('Pomer medium/high CVE u hostu')
	plt.tight_layout()

	autolabel(rects1, "left")
	autolabel(rects2, "right")
	fig.savefig(name_of_file + '_med_high_cves.pdf', bbox_inches='tight', format='pdf')
	fig.savefig(name_of_file + '_med_high_cves.png', bbox_inches='tight', format='png')
	
