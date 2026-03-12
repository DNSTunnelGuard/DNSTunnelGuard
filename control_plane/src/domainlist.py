class DomainList:
    """
    List of domains sourced from a file.

    One domain per line, seperated by new line
    """

    def __init__(self, path: str):
        self.domain_set = set()
        self.path = path

        with open(path, "r") as f:
            for line in f:
                domain = line.strip()
                self.domain_set.add(domain)

    def __iter__(self):
        return iter(self.domain_set)

    def __contains__(self, domain: str):
        return domain in self.domain_set

    def has_domain(self, domain: str) -> bool:
        if domain.endswith("."):
            domain = domain[:-1]

        return domain in self.domain_set

    def update(self, domain: str):
        if domain in self.domain_set:
            return
        with open(self.path, "a") as f:
            f.write(domain + "\n")

        self.domain_set.add(domain)

    def remove(self, domain: str):
        if domain in self.domain_set:
            self.domain_set.remove(domain)
        # TODO update in storage

    def _load(self, path: str):
        with open(path, "r") as f:
            for line in f:
                domain = line.split(",")[1].strip()
                self.domain_set.add(domain)
