from pyswip import Prolog
import csv

prolog = Prolog()

unique_data = set()

with open('Dataset/cybersecurity_attacks.csv', 'r') as csv_file:
    csv_reader = csv.DictReader(csv_file)

    for row in csv_reader:
        data_tuple = (row['Protocol'], row['Traffic Type'], row['Attack Type'])
        unique_data.add(data_tuple)


with open('protocols_involved.pl', 'w') as pl_file:
    for data in unique_data:
        pl_file.write(f"protocols_involved('{data[0]}', '{data[1]}', '{data[2]}').\n")
