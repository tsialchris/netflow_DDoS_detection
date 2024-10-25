def line_splitter(line, arg):
    # 2024-10-25 10:45:30,779 - INFO - || Misuse Category: total_traffic || dst4_addr: 212.205.221.3 || metric: bps || threshold: 100000 || value: 1336629 || Flow ID: 2dd147dc8aeb119f2d94f2f8186502c7bacffe8687457d76e56a5d6de34a60314584a6aa8571be2eeedf7d149d0e66515c600ddc619bcd553942aaee71b196aa ||
    if arg in line:
        line = line.strip()
        arg_split = line.split(arg)
        arg_split = arg_split[1].split(":")
        arg_split = arg_split[1].split("||")

        value = arg_split[0].strip()

        return value