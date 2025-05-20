package io.getarrays.authorizationserver.domain;

import nl.basjes.parse.useragent.UserAgentAnalyzer;

public class Analyzer {
    private static UserAgentAnalyzer INSTANCE;

    public static UserAgentAnalyzer getInstance() {
        if (INSTANCE == null) {
            INSTANCE = UserAgentAnalyzer
                    .newBuilder()
                    .hideMatcherLoadStats()
                    .withCache(1000)
                    .build();
        }
        return INSTANCE;
    }
}
