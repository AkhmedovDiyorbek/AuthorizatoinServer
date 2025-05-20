package io.getarrays.authorizationserver.repository.impl;

import io.getarrays.authorizationserver.exception.ApiException;
import io.getarrays.authorizationserver.model.User;
import io.getarrays.authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

import java.util.Map;

import static io.getarrays.authorizationserver.query.UserQuery.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository {
    private final JdbcClient jdbc;

    @Override
    public User getUserByUuid(String userUuid) {
        try{
            return jdbc
                    .sql(SELECT_USER_BY_USER_UUID_QUERY)
                    .param("userUuid", userUuid)
                    .query(User.class)
                    .single();
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException(String.format("No user found by UUID: %s", userUuid));
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

    @Override
    public User getUserByEmail(String email) {
        try{
            return jdbc
                    .sql(SELECT_USER_BY_EMAIL_QUERY)
                    .param("email", email)
                    .query(User.class)
                    .single();
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException(String.format("No user found by email: %s", email));
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

    @Override
    public void resetLoginAttempts(String userUuid) {
        try{
            jdbc.sql(RESET_LOGIN_ATTEMPTS_QUERY).param("userUuid", userUuid).update();
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException(String.format("No user found by UUID: %s", userUuid));
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

    @Override
    public void updateLoginAttempts(String email) {
        try{
            jdbc.sql(UPDATE_LOGIN_ATTEMPTS_QUERY).param("email", email).update();
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException(String.format("No user found by email: %s", email));
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

    @Override
    public void setLastLogin(Long userId) {
        try{
            jdbc.sql(SET_LAST_LOGIN_QUERY).param("userId", userId).update();
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException(String.format("No user found by User ID: %s", userId));
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

    @Override
    public void addLoginDevice(Long userId, String device, String client, String ipAddress) {
        try{
            jdbc.sql(INSERT_NEW_DEVICE_QUERY).params(Map.of("userId", userId, "device", device, "client", client,"ipAddress", ipAddress)).update();
        }catch (EmptyResultDataAccessException exception){
            log.error(exception.getMessage());
            throw new ApiException(String.format("No user found by User ID: %s", userId));
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again later.");
        }
    }

}
