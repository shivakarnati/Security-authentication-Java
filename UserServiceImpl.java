package com.lollie.web.engine.service.serviceimpl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.lollie.web.engine.db.entity.*;
import com.lollie.web.engine.db.repository.*;
import com.lollie.web.engine.dto.InstamojoAccessTokenRes;
import com.lollie.web.engine.dto.ProfileDto;
import com.lollie.web.engine.dto.request.*;
import com.lollie.web.engine.dto.response.*;
import com.lollie.web.engine.security.JwtTokenProvider;
import com.lollie.web.engine.service.UserService;
import com.lollie.web.engine.utility.Util;
import com.lollie.web.engine.utility.constants.*;
import com.restfb.DefaultFacebookClient;
import com.restfb.FacebookClient;
import com.restfb.Parameter;
import com.restfb.types.User;
import okhttp3.*;
import okio.Buffer;
import okio.BufferedSource;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.*;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private VerifyRegisterUserRepo verifyRegisterUserRepo;

    @Autowired
    private AppUserRepo appUserRepo;

    @Autowired
    private UserLocationRepo userLocationRepo;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Value("${pageItemSize}")
    private Integer pageItemSize;

    @Autowired
    private CommentRepo commentRepo;

    @Autowired
    private CommentLikeRepo commentLikeRepo;

    @Autowired
    private JavaMailSender sender;

    @Autowired
    private TemplateEngine templateEngine;

    @Value("${textlocal.apikey}")
    private String textLocalAPIKey;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private WordburnWinnersRepo wordburnWinnersRepo;

    @Autowired
    private AppUserTokenRepo appUserTokenRepo;

    @Autowired
    private NotificationRepo notificationRepo;

    @Value("${clientId}")
    private String clientId;

    @Value("${clientSecret}")
    private String clientSecret;

    @Value("${webGoogleClientId}")
    private String webGoogleClientId;

    @Value("${androidGoogleClientId}")
    private String androidGoogleClientId;


    @Override
    public ResponseEntity updateProfile(ProfileDto profileDto, Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        if (profileDto.getGender() != null)
            appUser.setGender(Gender.valueOf(profileDto.getGender()));

        if (profileDto.getEmailAddress() != null && !profileDto.getEmailAddress().isEmpty()) {
            if (!Util.getInstance().checkEmailValidation(profileDto.getEmailAddress())) {
                ApiResponse apiResponse = new ApiResponse(false, "Please enter valid email.");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            AppUser existAppUser = appUserRepo.findByEmailAddress(profileDto.getEmailAddress());
            if (existAppUser != null && !existAppUser.getId().equals(appUser.getId())) {
                ApiResponse apiResponse = new ApiResponse(false, "Email already exist.");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            appUser.setEmailAddress(profileDto.getEmailAddress());
        }

        if (profileDto.getFullName() != null && !profileDto.getFullName().isEmpty()) {
            appUser.setName(profileDto.getFullName());
        }

        if (profileDto.getImageUrl() != null && !profileDto.getImageUrl().isEmpty()) {
            appUser.setDpLink(profileDto.getImageUrl());
        }

        if (profileDto.getUserLocation() != null) {
            UserLocation userLocation = new UserLocation();
            if (profileDto.getUserLocation().getId() != null && profileDto.getUserLocation().getId() > 0) {
                userLocation = userLocationRepo.getOne(profileDto.getUserLocation().getId());
                userLocation.setStreet(profileDto.getUserLocation().getStreet());
                userLocation.setCity(profileDto.getUserLocation().getCity());
                userLocation.setState(profileDto.getUserLocation().getState());
                userLocation.setPincode(profileDto.getUserLocation().getPincode());
                userLocationRepo.save(userLocation);
            } else {
                userLocation.setStreet(profileDto.getUserLocation().getStreet());
                userLocation.setCity(profileDto.getUserLocation().getCity());
                userLocation.setState(profileDto.getUserLocation().getState());
                userLocation.setPincode(profileDto.getUserLocation().getPincode());
                userLocationRepo.save(userLocation);
            }
            appUser.setUserLocation(userLocation);
        }
        appUserRepo.save(appUser);
        ProfileDto profileResDto = new ProfileDto(appUser);
        ApiResponse apiResponse = new ApiResponse(true, "Profile updated successfully!", profileResDto);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity sendOtp(SendOtpRequestDto sendOtpRequestDto) {
        String message = "";
        String otp = generateOTP();
        String uniqueId = getUniqueId();
        VerifyRegisterUser verifyRegisterUser = new VerifyRegisterUser();
        String loginMessage = "is your OTP to login to Lolleey App. This will be valid for next 5 min. It is advised not to share your OTP with anybody. Welcome back to Lolleey!";
        String registrationMessage = "is your OTP to register with Lolleey. It will be valid for the next 5 minutes. Welcome to Lolleey. Keep Commenting, Keep Sharing, Keep Winning.";
        String forgotPswdMessage = "is your OTP to update your password. This is valid for next 5 min. Contact support@lolleey.com if you have not initiated it.";
        AppUser appUser = appUserRepo.findByMobileNumber(sendOtpRequestDto.getMobileNumber());
        if (sendOtpRequestDto.getUniqueId() != null && sendOtpRequestDto.getUniqueId().length() > 0) {
            verifyRegisterUser = verifyRegisterUserRepo.findByUniqueId(sendOtpRequestDto.getUniqueId());
            verifyRegisterUser.setUniqueId(uniqueId);
            verifyRegisterUser.setOtp(Long.valueOf(otp));
            if (sendOtpRequestDto.getRequestPurpose().equals(OtpRequestPurpose.REGISTRATION.toString())) {
                if (appUser != null) {
                    message = otp + " " + loginMessage;
                } else {
                    message = otp + " " + registrationMessage;
                }
            } else if (sendOtpRequestDto.getRequestPurpose().equals(OtpRequestPurpose.PASSWORD.toString())) {
                message = otp + " " + forgotPswdMessage;
            }
        } else {
            if (sendOtpRequestDto.getRequestPurpose().equals(OtpRequestPurpose.REGISTRATION.toString())) {
                if (appUser != null) {
                    message = otp + " " + loginMessage;
                    verifyRegisterUser.setOtp(Long.valueOf(otp));
                    verifyRegisterUser.setUniqueId(uniqueId);
                    verifyRegisterUser.setMobileNumber(sendOtpRequestDto.getMobileNumber());
                    verifyRegisterUser.setRequestPurpose(OtpRequestPurpose.LOGIN);
                } else {
                    message = otp + " " + registrationMessage;
                    verifyRegisterUser.setOtp(Long.valueOf(otp));
                    verifyRegisterUser.setUniqueId(uniqueId);
                    verifyRegisterUser.setMobileNumber(sendOtpRequestDto.getMobileNumber());
                    verifyRegisterUser.setRequestPurpose(OtpRequestPurpose.REGISTRATION);
                }
            } else if (sendOtpRequestDto.getRequestPurpose().equals(OtpRequestPurpose.PASSWORD.toString())) {
                message = otp + " " + forgotPswdMessage;
                verifyRegisterUser.setOtp(Long.valueOf(otp));
                verifyRegisterUser.setUniqueId(uniqueId);
                verifyRegisterUser.setMobileNumber(sendOtpRequestDto.getMobileNumber());
                verifyRegisterUser.setRequestPurpose(OtpRequestPurpose.PASSWORD);
            }
        }

        try {
            String smsStatus = sendSms(sendOtpRequestDto.getMobileNumber(), message);

            SmsSentResponse smsSentResponse = objectMapper.readValue(smsStatus, SmsSentResponse.class);

            if (smsSentResponse.getStatus().equalsIgnoreCase("success")) {
                verifyRegisterUser.setStatus(OtpStatus.SENT);
                verifyRegisterUserRepo.save(verifyRegisterUser);
                Map<String, Object> otpResponse = new HashMap<>();
                otpResponse.put("uniqueId", uniqueId);
                ApiResponse apiResponse = new ApiResponse(true, "OTP sent successful!", otpResponse);
                return ResponseEntity.ok(apiResponse);
            } else {
                verifyRegisterUser.setStatus(OtpStatus.FAILED);
                verifyRegisterUserRepo.save(verifyRegisterUser);
                ApiResponse apiResponse = new ApiResponse(false, "Cannot send OTP now. Please try again");
                return ResponseEntity.badRequest().body(apiResponse);
            }
        } catch (IOException e) {
            verifyRegisterUser.setStatus(OtpStatus.FAILED);
            verifyRegisterUserRepo.save(verifyRegisterUser);
            ApiResponse apiResponse = new ApiResponse(false, "Cannot send OTP now. Please try again");
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @Override
    public ResponseEntity verifyOtp(VerifyOtpRequestDto verifyOtpRequestDto) {
        VerifyRegisterUser verifyRegisterUser = verifyRegisterUserRepo.findByUniqueId(verifyOtpRequestDto.getUniqueId());
        AppUser appUser = appUserRepo.findByMobileNumber(verifyRegisterUser.getMobileNumber());
        if (verifyOtpRequestDto.getOtp().equals(verifyRegisterUser.getOtp())) {
            if (appUser != null) {
                if (appUser.getMobileNumber() != null) {
                    if (!appUser.getIsActive()) {
                        ApiResponse apiResponse = new ApiResponse(false, "Your account deativated. Please contact admin to active!");
                        return ResponseEntity.badRequest().body(apiResponse);
                    }
                    String authToken = jwtTokenProvider.createToken(appUser.getMobileNumber(), appUser.getRole());
                    RegistrationResDto userContactInfoRes = new RegistrationResDto(appUser, authToken);
                    verifyRegisterUser.setStatus(OtpStatus.VERIFIED);
                    verifyRegisterUserRepo.save(verifyRegisterUser);
                    ApiResponse apiResponse = new ApiResponse(true, "OTP verification successful!", userContactInfoRes);
                    return ResponseEntity.ok(apiResponse);
                }
            }
            verifyRegisterUser.setStatus(OtpStatus.VERIFIED);
            verifyRegisterUserRepo.save(verifyRegisterUser);
            ApiResponse apiResponse = new ApiResponse(true, "OTP verification successful!");
            return ResponseEntity.ok(apiResponse);
        } else {
            ApiResponse apiResponse = new ApiResponse(false, "Invalid OTP! Please enter valid OTP and try again!");
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @Override
    public ResponseEntity registerUser(RegistrationRequestDto registrationRequestDto) {
        AppUser appUser = new AppUser();
        VerifyRegisterUser verifyRegisterUser = verifyRegisterUserRepo.findByUniqueId(registrationRequestDto.getUniqueId());
        if (!verifyRegisterUser.getStatus().equals(OtpStatus.VERIFIED)) {
            ApiResponse apiResponse = new ApiResponse(false, "Please verify your mobile number with OTP!");
            return ResponseEntity.badRequest().body(apiResponse);
        }
        if (registrationRequestDto.getEmail() != null && registrationRequestDto.getEmail().trim().length() > 0) {
            AppUser existAppUser = appUserRepo.findByEmailAddress(registrationRequestDto.getEmail());
            if (existAppUser != null) {
                ApiResponse apiResponse = new ApiResponse(false, "Email address already exist! Please enter different email.");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            if (!Util.getInstance().checkEmailValidation(registrationRequestDto.getEmail())) {
                ApiResponse apiResponse = new ApiResponse(false, "Please enter valid email.");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            appUser.setEmailAddress(registrationRequestDto.getEmail());
        }
        Util.getInstance().notNullAndNotEmpty(registrationRequestDto.getName(), "Name can't be empty!");
        appUser.setName(registrationRequestDto.getName());

        Util.getInstance().notNullAndNotEmpty(registrationRequestDto.getPassword(), "PASSWORD can't be empty!");
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String bCryptPassword = bCryptPasswordEncoder.encode(registrationRequestDto.getPassword());
        appUser.setPassword(bCryptPassword);
        appUser.setMobileNumber(verifyRegisterUser.getMobileNumber());
        appUser.setRole(Role.USER);
        appUser.setIsActive(Boolean.TRUE);
        appUserRepo.save(appUser);
        String authToken = jwtTokenProvider.createToken(appUser.getMobileNumber(), appUser.getRole());
        try {
            if (appUser.getEmailAddress() != null && appUser.getEmailAddress().length() > 0) {
                String userName = appUser.getName();
                String subject = "Lolleey Registration Successful";
                Map<String, Object> message = new HashMap<>();
                message.put("user", userName);
                sendEmail(appUser.getEmailAddress(), subject, message);
            }
        } catch (Exception e) {
            Util.LOGGER.error(e.getMessage());
        }
        RegistrationResDto userRegistrationResInfo = new RegistrationResDto(appUser, authToken);
        ApiResponse apiResponse = new ApiResponse(true, "REGISTRATION Successful!", userRegistrationResInfo);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity userLogin(LoginRequestDto loginRequestDto) {
        try {
            AppUser appUser;
            if (loginRequestDto.getLoginId() == null) {
                ApiResponse apiResponse = new ApiResponse(false, "LoginId can't be empty. Please enter loginId!");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            if (loginRequestDto.getPassword() == null) {
                ApiResponse apiResponse = new ApiResponse(false, "PASSWORD can't be empty. Please enter password!");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            if (loginRequestDto.getLoginId().contains("@")) {
                if (!Util.getInstance().checkEmailValidation(loginRequestDto.getLoginId())) {
                    ApiResponse apiResponse = new ApiResponse(false, "Please enter valid email.");
                    return ResponseEntity.badRequest().body(apiResponse);
                }
                appUser = appUserRepo.findByEmailAddress(loginRequestDto.getLoginId());
            } else {
                if (!Util.getInstance().checkMobileNumberValidation(loginRequestDto.getLoginId())) {
                    ApiResponse apiResponse = new ApiResponse(false, "Please enter valid mobile number.");
                    return ResponseEntity.badRequest().body(apiResponse);
                }
                appUser = appUserRepo.findByMobileNumber(loginRequestDto.getLoginId());
            }

            if (appUser == null) {
                ApiResponse apiResponse = new ApiResponse(false, "No user found with this loginId");
                return ResponseEntity.badRequest().body(apiResponse);
            }

            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
            if (!bCryptPasswordEncoder.matches(loginRequestDto.getPassword(), appUser.getPassword())) {
                ApiResponse apiResponse = new ApiResponse(false, "please enter correct password");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            if (!appUser.getIsActive()) {
                ApiResponse apiResponse = new ApiResponse(false, "Because of misusage your account is suspended by Admin. Please contact our customer support to active!");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            String authToken = jwtTokenProvider.createToken(appUser.getMobileNumber(), appUser.getRole());
            RegistrationResDto userLoginResponseInfo = new RegistrationResDto(appUser, authToken);
            ApiResponse apiResponse = new ApiResponse(true, "Welcome to lollie", userLoginResponseInfo);
            return ResponseEntity.ok(apiResponse);

        } catch (Exception e) {
            ApiResponse apiResponse = new ApiResponse(false, "Something went wrong. Please try again!");
            return ResponseEntity.badRequest().body(apiResponse);
        }

    }

    @Override
    public ResponseEntity checkIsAdmin(Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        Map<String, Object> map = new HashMap<>();
        map.put("role", appUser.getRole().toString());
        if (appUser.getRole().equals(Role.ADMIN)) {
            map.put("isAdmin", Boolean.TRUE);
        } else {
            map.put("isAdmin", Boolean.FALSE);
        }
        ApiResponse apiResponse = new ApiResponse(true, "Success", map);
        return ResponseEntity.ok(apiResponse);

    }

    @Override
    public ResponseEntity getLatestComments(Authentication authentication, PaginationAndSortRequestDto paginationAndSortRequestDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        Pageable pageable = PageRequest.of(paginationAndSortRequestDto.getRequestPage(), pageItemSize, Sort.Direction.fromString(paginationAndSortRequestDto.getSortOrder()), paginationAndSortRequestDto.getSortBy());
        Page<Comment> commentPage = commentRepo.findAllByCommentedUserAndWordburnIsActiveTrue(appUser, pageable);
        if (commentPage == null) {
            ApiResponse apiResponse = new ApiResponse(false, "No comments found");
            return ResponseEntity.ok(apiResponse);
        }
        List<CommentResponseDto> commentResponseDtoList = new ArrayList<>();
        for (Comment comment :
                commentPage) {
            boolean isLiked = false;
            CommentLike commentLike = commentLikeRepo.findByCommentAndAppUserAndIsActiveTrue(comment, appUser);
            if (commentLike != null)
                isLiked = commentLike.getAppUser().equals(appUser);
            CommentResponseDto commentResponseDto = new CommentResponseDto(comment, isLiked, true);
            commentResponseDtoList.add(commentResponseDto);
        }

        Map<String, Object> resMap = new HashMap<>();

        resMap.put("commentList", commentResponseDtoList);
        resMap.put("currentPage", commentPage.getNumber());
        resMap.put("totalPages", commentPage.getTotalPages());

        ApiResponse apiResponse = new ApiResponse(true, "Successful!", resMap);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity changePassword(ChangePasswordDto changePasswordDto, Authentication authentication) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        ApiResponse apiResponse;
        if (changePasswordDto != null && authentication != null) {
            AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
            if (appUser == null) {
                apiResponse = new ApiResponse(Boolean.FALSE, "No user found. Please login and try again!");
                return ResponseEntity.badRequest().body(apiResponse);
            }
            if (!bCryptPasswordEncoder.matches(changePasswordDto.getCurrentPassword(), appUser.getPassword())) {
                apiResponse = new ApiResponse(Boolean.FALSE, "Incorrect current password. Please enter valid password!");
                return ResponseEntity.badRequest().body(apiResponse);
            }

            if (bCryptPasswordEncoder.matches(changePasswordDto.getNewPassword(), appUser.getPassword())) {
                apiResponse = new ApiResponse(Boolean.FALSE, "New password couldn't be same as current password. Please enter different password!");
                return ResponseEntity.badRequest().body(apiResponse);
            }

            if (changePasswordDto.getNewPassword().equals(changePasswordDto.getConfirmPassword())) {
                String newBCryptPassword = bCryptPasswordEncoder.encode(changePasswordDto.getNewPassword());
                appUser.setPassword(newBCryptPassword);
                appUserRepo.save(appUser);
                apiResponse = new ApiResponse(true, "PASSWORD changed successfully!");
                return ResponseEntity.ok(apiResponse);
            } else {
                apiResponse = new ApiResponse(Boolean.FALSE, "Passwords do not match. Please enter both password and confirm password should be same!");
                return ResponseEntity.badRequest().body(apiResponse);
            }
        } else {
            apiResponse = new ApiResponse(Boolean.FALSE, "OOPs something went wrong. Please try again!");
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @Override
    public ResponseEntity resetPassword(ResetPasswordDto resetPasswordDto) {
        ApiResponse apiResponse;
        VerifyRegisterUser verifyRegisterUser = verifyRegisterUserRepo.findByUniqueId(resetPasswordDto.getUniqueId());
        AppUser appUser = appUserRepo.findByMobileNumber(verifyRegisterUser.getMobileNumber());
        if (appUser == null) {
            apiResponse = new ApiResponse(Boolean.FALSE, "No user found with this PhoneNumber");
            return ResponseEntity.badRequest().body(apiResponse);
        }

        if (!resetPasswordDto.getOtp().equals(verifyRegisterUser.getOtp())) {
            apiResponse = new ApiResponse(false, "Invalid OTP! Please enter valid OTP and try again!");
            return ResponseEntity.badRequest().body(apiResponse);
        }

        if (resetPasswordDto.getOtp().equals(verifyRegisterUser.getOtp())) {
            verifyRegisterUser.setStatus(OtpStatus.VERIFIED);
            verifyRegisterUserRepo.save(verifyRegisterUser);
        }

        if (!verifyRegisterUser.getStatus().equals(OtpStatus.VERIFIED)) {
            apiResponse = new ApiResponse(Boolean.FALSE, "Please verify your mobile number with OTP");
            return ResponseEntity.badRequest().body(apiResponse);
        }


        if (resetPasswordDto.getNewPassword().equals(resetPasswordDto.getConfirmPassword())) {
            BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
            String bCryptPassword = bCryptPasswordEncoder.encode(resetPasswordDto.getNewPassword());
            appUser.setPassword(bCryptPassword);
            appUserRepo.save(appUser);
            apiResponse = new ApiResponse(true, "Password updated successfully!");
            return ResponseEntity.ok(apiResponse);
        } else {
            apiResponse = new ApiResponse(Boolean.FALSE, "Passwords do not match.Please enter password and confirm password should be same!");
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @Override
    public ResponseEntity getUserCreditsCommentsWinnings(Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        CreditAndWinningsDto creditAndWinningsDto = new CreditAndWinningsDto();
        if (appUser.getCredits() != null && appUser.getCredits() != 0) {
            creditAndWinningsDto.setCredits(Util.getInstance().formatDecimalNumber(appUser.getCredits()));
        } else {
            creditAndWinningsDto.setCredits(appUser.getCredits());
        }
        creditAndWinningsDto.setCommentCount(commentRepo.countByCommentedUser(appUser));
        Double winningCredits;
        if (wordburnWinnersRepo.sumOfWinningCredits(appUser) != null) {
            winningCredits = Util.getInstance().formatDecimalNumber(wordburnWinnersRepo.sumOfWinningCredits(appUser));
        } else {
            winningCredits = 0.0;
        }
        creditAndWinningsDto.setWinningCredits(winningCredits);
        creditAndWinningsDto.setWordburnCount(wordburnWinnersRepo.countByWinnerDistinctWordburn(appUser));

        ApiResponse apiResponse = new ApiResponse(true, "User data fetched successfully", creditAndWinningsDto);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity setUserDeviceToken(Authentication authentication, DeviceTokenDto deviceTokenDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        AppUserToken appUserToken = appUserTokenRepo.findByAppUserAndDeviceType(appUser, DeviceType.valueOf(deviceTokenDto.getDeviceType()));
        if (appUserToken != null) {
            appUserToken.setDeviceToken(deviceTokenDto.getDeviceToken());
            appUserTokenRepo.save(appUserToken);
        } else {
            appUserToken = new AppUserToken();
            appUserToken.setAppUser(appUser);
            appUserToken.setDeviceToken(deviceTokenDto.getDeviceToken());
            appUserToken.setDeviceType(DeviceType.valueOf(deviceTokenDto.getDeviceType()));
            appUserTokenRepo.save(appUserToken);
        }
        ApiResponse apiResponse = new ApiResponse(true, "Token updated successfully");
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public String getInstamojoToken() {
        OkHttpClient client = new OkHttpClient();
        okhttp3.MediaType mediaType = okhttp3.MediaType.parse("application/x-www-form-urlencoded");
        RequestBody body = RequestBody.create(mediaType, "grant_type=client_credentials&client_id=" + clientId + "&client_secret=" + clientSecret);
        Request request = new Request.Builder()
                .url("https://www.instamojo.com/oauth2/token/")
                .post(body)
                .addHeader("content-type", "application/x-www-form-urlencoded")
                .build();
        ResponseBody responseBody = null;
        String responseBodyString = null;
        JSONObject jsonObj = null;
        InstamojoAccessTokenRes instamojoAccessTokenRes = null;
        String accessToken = null;
        try {
            JSONObject jsonObject = new JSONObject();
            Response response = client.newCall(request).execute();
            MediaType contentType = response.body().contentType();
            responseBody = ResponseBody.create(contentType, jsonObject.toString());
            BufferedSource source = response.body().source();
            source.request(Long.MAX_VALUE); // Buffer the entire body.
            Buffer buffer = source.buffer();
            responseBodyString = buffer.clone().readString(Charset.forName("UTF-8"));
            Util.LOGGER.info("responseBodyString" + responseBodyString);
            if (responseBodyString.isEmpty()) {
                return null;
            }
            jsonObj = new JSONObject(responseBodyString);
            instamojoAccessTokenRes = new InstamojoAccessTokenRes();
            accessToken = "production" + jsonObj.getString("access_token");
           /* instamojoAccessTokenRes.setAccess_token("production" + jsonObj.getString("access_token"));
            instamojoAccessTokenRes.setExpires_in(jsonObj.getLong("expires_in"));
            instamojoAccessTokenRes.setToken_type(jsonObj.getString("token_type"));
            instamojoAccessTokenRes.setScope(jsonObj.getString("scope"));*/
            Util.LOGGER.info("jsonObj" + jsonObj);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            responseBody.close();
            return accessToken;
        }

    }

    @Override
    public ResponseEntity getUserNotifications(Authentication authentication, PaginationAndSortRequestDto paginationAndSortRequestDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        Pageable pageable = PageRequest.of(paginationAndSortRequestDto.getRequestPage(), pageItemSize, Sort.Direction.fromString(paginationAndSortRequestDto.getSortOrder()), paginationAndSortRequestDto.getSortBy());
        Page<Notification> notificationPage = notificationRepo.findAllByAppUser(appUser, pageable);
        if (notificationPage == null) {
            ApiResponse apiResponse = new ApiResponse(false, "No data found");
            return ResponseEntity.ok(apiResponse);
        }

        Integer unreadCount = notificationRepo.countByAppUserAndIsReadFalse(appUser);

        List<NotificationResDto> notificationResDtoList = new ArrayList<>();
        for (Notification notification :
                notificationPage) {
            NotificationResDto notificationResDto = new NotificationResDto();
            notificationResDto.setId(notification.getId());
            notificationResDto.setMessage(notification.getMessage());
            notificationResDto.setWordburnId(notification.getWordburnId());
            notificationResDto.setCommentId(notification.getCommentId());
            notificationResDto.setIsRead(notification.getIsRead());
            notificationResDtoList.add(notificationResDto);
        }
        Map<String, Object> map = new HashMap<>();
        map.put("notificationList", notificationResDtoList);
        map.put("currentPage", notificationPage.getNumber());
        map.put("totalPages", notificationPage.getTotalPages());
        map.put("unreadCount", unreadCount);
        ApiResponse apiResponse = new ApiResponse(true, "Notification list", map);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity getReadNotification(Authentication authentication, RequestByIdDto requestByIdDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        Notification notification = notificationRepo.findByIdAndAppUserAndIsReadFalse(requestByIdDto.getId(), appUser);
        if (notification == null) {
            ApiResponse apiResponse = new ApiResponse(false, "No data found");
            return ResponseEntity.ok(apiResponse);
        }
        notification.setIsRead(Boolean.TRUE);
        notificationRepo.save(notification);
        ApiResponse apiResponse = new ApiResponse(true, "Updated successfully");
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity markAllAsRead(Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        List<Notification> notificationList = notificationRepo.findAllByAppUserAndIsReadFalse(appUser);
        for (Notification notification : notificationList) {
            notification.setIsRead(Boolean.TRUE);
            notificationRepo.save(notification);
        }
        ApiResponse apiResponse = new ApiResponse(true, "Updated successfully");
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public InstamojoAccessTokenRes getInstamojoTokenForIos() {
        OkHttpClient client = new OkHttpClient();

        okhttp3.MediaType mediaType = okhttp3.MediaType.parse("application/x-www-form-urlencoded");
        RequestBody body = RequestBody.create(mediaType, "grant_type=client_credentials&client_id=" + "W1yXJvr59crRz0WPUTdx0Xp54l2DoB5PehexQV47" + "&client_secret=" + "zQPMAcR47Iw0JkxHOIRemjOafDyqFZsyc2Ih04t1BsNRZswNKLXXhQkDW6mVtNusNCk7MUz6fsWigIxZHBkg5YBJto3mo4qMX5rQSgFHUIcn6CN8zRETGMIFaoAtPdK8");
        Request request = new Request.Builder()
                .url("https://www.instamojo.com/oauth2/token/")
                .post(body)
                .addHeader("content-type", "application/x-www-form-urlencoded")
                .build();
        ResponseBody responseBody = null;
        String responseBodyString = null;
        JSONObject jsonObj = null;
        InstamojoAccessTokenRes instamojoAccessTokenRes = null;
        String accessToken = null;
        try {
            JSONObject jsonObject = new JSONObject();
            Response response = client.newCall(request).execute();
            MediaType contentType = response.body().contentType();
            responseBody = ResponseBody.create(contentType, jsonObject.toString());
            BufferedSource source = response.body().source();
            source.request(Long.MAX_VALUE); // Buffer the entire body.
            Buffer buffer = source.buffer();
            responseBodyString = buffer.clone().readString(Charset.forName("UTF-8"));
            Util.LOGGER.info("responseBodyString" + responseBodyString);
            if (responseBodyString.isEmpty()) {
                return null;
            }
            jsonObj = new JSONObject(responseBodyString);
            instamojoAccessTokenRes = new InstamojoAccessTokenRes();
            instamojoAccessTokenRes.setAccess_token(jsonObj.getString("access_token"));
            instamojoAccessTokenRes.setExpires_in(jsonObj.getLong("expires_in"));
            instamojoAccessTokenRes.setToken_type(jsonObj.getString("token_type"));
            instamojoAccessTokenRes.setScope(jsonObj.getString("scope"));
            Util.LOGGER.info("jsonObj" + jsonObj);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            responseBody.close();
            return instamojoAccessTokenRes;
        }

    }

    @Override
    public ResponseEntity loginWithGoogle(SocialLoginDto socialLoginDto) {
        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), JacksonFactory.getDefaultInstance())
                .setAudience(Arrays.asList(webGoogleClientId, androidGoogleClientId))
                .build();
        GoogleIdToken idToken = null;
        try {
            idToken = verifier.verify(socialLoginDto.getToken());
            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();

                String userId = payload.getSubject();
                Util.LOGGER.info("User ID: " + userId);

                String email = payload.getEmail();
                AppUser appUser = appUserRepo.findByEmailAddress(email);

                if (appUser != null) {
                    String authToken;
                    if (appUser.getMobileNumber() != null) {
                        authToken = jwtTokenProvider.createToken(appUser.getMobileNumber(), appUser.getRole());
                    } else {
                        authToken = jwtTokenProvider.createToken(appUser.getEmailAddress(), appUser.getRole());
                    }
                    RegistrationResDto userRegistrationResInfo = new RegistrationResDto(appUser, authToken);
                    return ResponseEntity.ok(userRegistrationResInfo);
                }
                String name = (String) payload.get("name");
                String pictureUrl = (String) payload.get("picture");
                appUser = new AppUser();
                appUser.setName(name);
                appUser.setDpLink(pictureUrl);
                appUser.setEmailAddress(email);
                appUser.setRole(Role.USER);
                appUser.setIsActive(Boolean.TRUE);
                appUserRepo.save(appUser);
                String authToken = jwtTokenProvider.createToken(appUser.getEmailAddress(), appUser.getRole());
                try {
                    if (appUser.getEmailAddress() != null && appUser.getEmailAddress().length() > 0) {
                        String userName = appUser.getName();
                        String subject = "Lolleey Registration Successful";
                        Map<String, Object> message = new HashMap<>();
                        message.put("user", userName);
                        sendEmail(appUser.getEmailAddress(), subject, message);
                    }
                } catch (Exception e) {
                    Util.LOGGER.error(e.getMessage());
                }
                RegistrationResDto userRegistrationResInfo = new RegistrationResDto(appUser, authToken);
                ApiResponse apiResponse = new ApiResponse(true, "REGISTRATION Successful!", userRegistrationResInfo);
                return ResponseEntity.ok(apiResponse);
            } else {
                ApiResponse apiResponse = new ApiResponse(false, "Invalid ID token");
                return ResponseEntity.badRequest().body(apiResponse);
            }
        } catch (GeneralSecurityException e) {
            Util.LOGGER.error(e.getLocalizedMessage());
            ApiResponse apiResponse = new ApiResponse(false, "Something went wrong");
            return ResponseEntity.badRequest().body(apiResponse);
        } catch (IOException e) {
            Util.LOGGER.error(e.getLocalizedMessage());
            ApiResponse apiResponse = new ApiResponse(false, "Something went wrong");
            return ResponseEntity.badRequest().body(apiResponse);
        }
    }

    @Override
    public ResponseEntity loginWithFacebook(SocialLoginDto socialLoginDto) {

        FacebookClient facebookClient = new DefaultFacebookClient(socialLoginDto.getToken());
        User user = facebookClient.fetchObject("me", User.class, Parameter.with("fields", "name,email,picture"));
        AppUser appUser = appUserRepo.findByEmailAddress(user.getEmail());

        if (appUser != null) {
            String authToken;
            if (appUser.getMobileNumber() != null) {
                authToken = jwtTokenProvider.createToken(appUser.getMobileNumber(), appUser.getRole());
            } else {
                authToken = jwtTokenProvider.createToken(appUser.getEmailAddress(), appUser.getRole());
            }
            RegistrationResDto userRegistrationResInfo = new RegistrationResDto(appUser, authToken);
            return ResponseEntity.ok(userRegistrationResInfo);
        }
        appUser = new AppUser();

        appUser.setName(user.getName());
        appUser.setEmailAddress(user.getEmail());
        appUser.setDpLink(user.getPicture().getUrl());
        appUser.setIsActive(Boolean.TRUE);
        appUser.setRole(Role.USER);
        appUserRepo.save(appUser);
        String authToken = jwtTokenProvider.createToken(appUser.getEmailAddress(), appUser.getRole());
        try {
            if (appUser.getEmailAddress() != null && appUser.getEmailAddress().length() > 0) {
                String userName = appUser.getName();
                String subject = "Lolleey Registration Successful";
                Map<String, Object> message = new HashMap<>();
                message.put("user", userName);
                sendEmail(appUser.getEmailAddress(), subject, message);
            }
        } catch (Exception e) {
            Util.LOGGER.error(e.getMessage());
        }
        RegistrationResDto userRegistrationResInfo = new RegistrationResDto(appUser, authToken);
        ApiResponse apiResponse = new ApiResponse(true, "REGISTRATION Successful!", userRegistrationResInfo);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity logout(Authentication authentication, LogoutDto logoutDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }

        if (appUser == null) {
            ApiResponse apiResponse = new ApiResponse(false, "User not found");
            return ResponseEntity.badRequest().body(apiResponse);
        }

        AppUserToken appUserToken = appUserTokenRepo.findByAppUserAndDeviceTypeAndIsLoggedInTrue(appUser, DeviceType.valueOf(logoutDto.getDeviceType().toUpperCase()));

        if (appUserToken == null) {
            ApiResponse apiResponse = new ApiResponse(false, "User not logged in");
            return ResponseEntity.badRequest().body(apiResponse);
        }

        appUserToken.setIsLoggedIn(Boolean.FALSE);
        appUserTokenRepo.save(appUserToken);

        return new ResponseEntity(HttpStatus.OK);
    }

    @Override
    public ResponseEntity getUserDetails(Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (appUser == null) {
            appUser = appUserRepo.findByEmailAddress(authentication.getName());
        }
        ProfileDto profileResDto = new ProfileDto(appUser);
        ApiResponse apiResponse = new ApiResponse(true, "Profile details", profileResDto);
        return ResponseEntity.ok(apiResponse);
    }


    private String generateOTP() {
        Random random = new Random();
        return String.format("%04d", random.nextInt(10000));
    }

    private String getUniqueId() {
        UUID key = UUID.randomUUID();
        return key.toString();
    }

    private String sendSms(String mobileNumber, String messageBody) {
        BufferedReader br = null;
        //Construct Data
        String apikey = "apiKey=" + textLocalAPIKey;
        String sender = "&sender=" + "LOLEEY";
        String message = "&message=" + messageBody;
        String number = "&numbers=91" + mobileNumber;

        try {
            //Send Data
            HttpURLConnection conn = (HttpURLConnection) new URL("https://api.textlocal.in/send/?").openConnection();
            String data = apikey + number + message + sender;
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Length", Integer.toString(data.length()));
            conn.getOutputStream().write(data.getBytes("UTF-8"));
            br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            final StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                stringBuilder.append(line);
            }

            br.close();

            return stringBuilder.toString();

        } catch (Exception ex) {
            Util.LOGGER.error(ex.getMessage());
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    Util.LOGGER.error(e.getMessage());
                }
            }
        }
        return null;
    }

    private void sendEmail(String emailId, String subject, Map<String, Object> message) throws Exception {

        final String templateFileName = "email-template"; //Name of the template file without extension
        String output = this.templateEngine.process(templateFileName, new Context(Locale.getDefault(), message));
        MimeMessage message1 = sender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message1);
        try {
            helper.setTo(emailId);
            helper.setSubject(subject);
            helper.setText(output, true);
            sender.send(message1);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}
