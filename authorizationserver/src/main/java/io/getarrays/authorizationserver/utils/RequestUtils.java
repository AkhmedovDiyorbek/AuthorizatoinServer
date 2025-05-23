package io.getarrays.authorizationserver.utils;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;

public class RequestUtils {
    public static String getMessage(HttpServletRequest request) {
        var status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if(status != null) {
            int statusCode = Integer.parseInt(status.toString());
            if(statusCode == HttpStatus.NOT_FOUND.value()) {
                return String.format("%s - Not Found Error", statusCode);
            }
            if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                return String.format("%s - Internal Server Error", statusCode);
            }
            if(statusCode == HttpStatus.FORBIDDEN.value()) {
                return String.format("%s - Forbidden Error", statusCode);
            }
        }
        return "An Error Occurred";
    }


}
