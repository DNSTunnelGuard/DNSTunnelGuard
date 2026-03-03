

from argparse import ArgumentParser



def main(): 

    parser = ArgumentParser(description="Generate DNS Perf input file from a list of domain names")

    parser.add_argument(
        "-l", "--domainlist", 
        required=False, 
        help="Path to domain list",
        default="../data/whitelist.txt"
    )

    parser.add_argument(
        "-c", "--count", 
        required=False,
        help="Number of queries to use",
        default=1000
    )

    args = parser.parse_args()

    counter = 0
    num_domains = int(args.count)
    with open(args.domainlist, "r") as f: 
        with open("perftest.txt", "w") as pt: 
            for line in f: 
                if counter > num_domains: 
                    break 
                pt.write(f"{line.strip()}. A\n")
                counter += 1


    
if __name__ == "__main__": 
    main()
    print("DNSPerf input generated to perftest.txt")




        
