# greenpapl
Greenbone Parser and Plotter

## Usage

Greenpapl takes input a csv file, export from Greenbone. Based on the number of hosts it will parse the csv, create reasonable subpart of the whole scope and will plot it to `pdf` and `png`.
The output is a plot of:
* Hosts with most critical CVEs sorted descendingly
* Hosts with highest number of CVEs sorted descendingly
* High/medium CVEs ratio of hosts sorted descendingly
