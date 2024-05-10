class userAgentException(Exception):

    def __init__(self, userAgent):
        self.userAgent = userAgent
        super().__init__(f"Unrecognized value in: {userAgent}")