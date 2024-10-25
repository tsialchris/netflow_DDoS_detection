

class Flow_Tracker:
    def __init__(self, hash_value, misuse_category,
                 dst4_addr, metric, metric_threshold, value):

        # also store the flow associated with the tracker
        # to have it available later for triggering
        # self.flow = flow

        self.isActive = True
        self.active_counter = 0

        self.flow_ID = hash_value
        self.misuse_category = misuse_category
        self.dst4_addr = dst4_addr
        self.metric = metric
        self.metric_threshold = metric_threshold
        self.value = value

    def increment_active_counter(self):
        self.active_counter = self.active_counter + 1
    