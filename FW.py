from Rule import Rule

class FW:
    def __init__(self, conf_file_path):
        with open(conf_file_path, 'r') as f:
            self.rules = [Rule(line) for line in f.readlines() if not line.startswith('#')]
        print("FW RULES\n=========================")
        for index, rule in enumerate(self.rules):
            print(f"{index}. {rule.field}: {rule.values}")
    

    def should_drop_packet(self, packet):
        invalid_status = False
        invalid_fields = {}
        for rule in self.rules:
            invalid_rule, invalid_field_value =  rule.check(packet)
            if invalid_rule:
                invalid_status = True 
                invalid_fields[rule.field] = invalid_field_value
        return invalid_status, invalid_fields