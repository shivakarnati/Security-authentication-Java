package com.lollie.web.engine.service.serviceimpl;

import com.lollie.web.engine.db.entity.*;
import com.lollie.web.engine.db.repository.*;
import com.lollie.web.engine.dto.request.ChangeUserStatusDto;
import com.lollie.web.engine.dto.request.PaginationAndSortRequestDto;
import com.lollie.web.engine.dto.request.WordburnWinnersRequestDto;
import com.lollie.web.engine.dto.response.ApiResponse;
import com.lollie.web.engine.dto.response.ClosingWordburnResponseDto;
import com.lollie.web.engine.dto.response.UserListResponseDto;
import com.lollie.web.engine.dto.response.WordburnWinnersResponseDto;
import com.lollie.web.engine.service.AdminService;
import com.lollie.web.engine.service.NotificationService;
import com.lollie.web.engine.utility.Util;
import com.lollie.web.engine.utility.constants.FeedType;
import com.lollie.web.engine.utility.constants.Role;
import com.lollie.web.engine.utility.constants.WinnerType;
import com.lollie.web.engine.utility.constants.WordburnStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class AdminServiceImpl implements AdminService {
    @Autowired
    private AppUserRepo appUserRepo;

    @Value("${pageItemSize}")
    private Integer pageItemSize;

    @Autowired
    private WordburnRepo wordburnRepo;

    @Autowired
    private WordburnWinnersRepo wordburnWinnersRepo;

    @Autowired
    private CommentRepo commentRepo;

    @Autowired
    private WordburnFeedRepo wordburnFeedRepo;

    @Autowired
    private NotificationService notificationService;

    @Autowired
    private NotificationRepo notificationRepo;

    @Override
    public ResponseEntity getUserList(Authentication authentication, PaginationAndSortRequestDto paginationAndSortRequestDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (!appUser.getRole().equals(Role.ADMIN)) {
            ApiResponse apiResponse = new ApiResponse(false, "You don't have permission");
            return ResponseEntity.ok(apiResponse);
        }
        Pageable pageable = PageRequest.of(paginationAndSortRequestDto.getRequestPage(), pageItemSize, Sort.Direction.fromString(paginationAndSortRequestDto.getSortOrder()), paginationAndSortRequestDto.getSortBy());
        Page<AppUser> appUserPage = appUserRepo.findAllByRole(Role.USER, pageable);
        if (appUserPage == null) {
            ApiResponse apiResponse = new ApiResponse(false, "No data found");
            return ResponseEntity.ok(apiResponse);
        }
        List<UserListResponseDto> userListResponseDtoList = new ArrayList<>();
        appUserPage.forEach(user -> {
            UserListResponseDto userListResponseDto = new UserListResponseDto();
            userListResponseDto.setId(user.getId());
            userListResponseDto.setName(user.getName());
            userListResponseDto.setEmail(user.getEmailAddress());
            userListResponseDto.setCredits(user.getCredits());
            userListResponseDto.setMobileNumber(user.getMobileNumber());
            userListResponseDto.setIsActive(user.getIsActive());
            userListResponseDtoList.add(userListResponseDto);
        });
        Map<String, Object> map = new HashMap<>();
        map.put("userList", userListResponseDtoList);
        map.put("currentPage", appUserPage.getNumber());
        map.put("totalPages", appUserPage.getTotalPages());

        ApiResponse apiResponse = new ApiResponse(true, "Successful!", map);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity checkWinners(WordburnWinnersRequestDto wordburnWinnersRequestDto, Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (!appUser.getRole().equals(Role.ADMIN)) {
            ApiResponse apiResponse = new ApiResponse(false, "You don't have permission");
            return ResponseEntity.ok(apiResponse);
        }

        Wordburn wordburn = wordburnRepo.findByIdAndIsActiveTrue(wordburnWinnersRequestDto.getWordburnId());
        if (wordburn == null) {
            ApiResponse apiResponse = new ApiResponse(false, "Wordburn not found");
            return ResponseEntity.ok(apiResponse);
        }
        if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.CANCEL_WORDBURN.toString())) {
            List<Comment> commentList = commentRepo.findAllByWordburnAndIsActiveTrue(wordburn);
            List<WordburnWinnersResponseDto> wordburnWinnersResponseDtoList = new ArrayList<>();
            commentList.forEach(comment -> {
                WordburnWinnersResponseDto wordburnWinnersResponseDto = new WordburnWinnersResponseDto();
                wordburnWinnersResponseDto.setUserName(comment.getCommentedUser().getName());
                wordburnWinnersResponseDto.setComment(comment.getCommentText());
                wordburnWinnersResponseDto.setLikes(comment.getLikes());
                wordburnWinnersResponseDto.setCredits(comment.getCredits());
                wordburnWinnersResponseDtoList.add(wordburnWinnersResponseDto);
            });
            ApiResponse apiResponse = new ApiResponse(true, "Successful!", wordburnWinnersResponseDtoList);
            return ResponseEntity.ok(apiResponse);
        }
        Long commentCount = commentRepo.countByWordburn(wordburn);
        Double totalCreditsOfWordburn = commentCount * wordburn.getCreditsPerComment();
        Long numberOfWinningComments = 0L;
        if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.LOLLEEY_STANDARD.toString())) {
            numberOfWinningComments = Math.round(wordburn.getCommentCount() * 0.12);
            if (numberOfWinningComments == 0) {
                ApiResponse apiResponse = new ApiResponse(true, "12% not feasable");
                return ResponseEntity.ok(apiResponse);
            }
        } else if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.ALL_WINNERS.toString())) {
            numberOfWinningComments = wordburn.getCommentCount();
        }
        if (numberOfWinningComments != 0) {
            List<BigInteger> likes = commentRepo.getTopDistinctComments(wordburn.getId(), numberOfWinningComments);
            Long noOfWinningLikesOfWordburn = 0L;
            List<Comment> winningComments = new ArrayList<>();
            for (BigInteger noLikes : likes) {
                if (noLikes.longValue() != 0) {
                    List<Comment> commentList = commentRepo.findAllByWordburnAndLikes(wordburn, noLikes.longValue());
                    for (Comment comment :
                            commentList) {
                        noOfWinningLikesOfWordburn += comment.getLikes();
                        winningComments.add(comment);
                    }
                    if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.LOLLEEY_STANDARD.toString()) && winningComments.size() >= numberOfWinningComments) {
                        break;
                    }
                }
            }

            if (noOfWinningLikesOfWordburn != 0) {
                Double creditsPerLike = totalCreditsOfWordburn / noOfWinningLikesOfWordburn;
                List<WordburnWinnersResponseDto> wordburnWinnersResponseDtoList = new ArrayList<>();
                winningComments.forEach(comment -> {
                    Double winningCredits = Util.getInstance().formatDecimalNumber(comment.getLikes() * creditsPerLike);
                    WordburnWinnersResponseDto wordburnWinnersResponseDto = new WordburnWinnersResponseDto();
                    wordburnWinnersResponseDto.setUserName(comment.getCommentedUser().getName());
                    wordburnWinnersResponseDto.setComment(comment.getCommentText());
                    wordburnWinnersResponseDto.setLikes(comment.getLikes());
                    wordburnWinnersResponseDto.setCredits(winningCredits);
                    wordburnWinnersResponseDtoList.add(wordburnWinnersResponseDto);
                });
                ApiResponse apiResponse = new ApiResponse(true, "Successful!", wordburnWinnersResponseDtoList);
                return ResponseEntity.ok(apiResponse);
            } else {
                ApiResponse apiResponse = new ApiResponse(false, "No likes for comments");
                return ResponseEntity.ok(apiResponse);
            }
        } else {
            ApiResponse apiResponse = new ApiResponse(false, "No comments found");
            return ResponseEntity.ok(apiResponse);
        }
    }

    @Override
    public ResponseEntity declareWinners(WordburnWinnersRequestDto wordburnWinnersRequestDto, Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (!appUser.getRole().equals(Role.ADMIN)) {
            ApiResponse apiResponse = new ApiResponse(false, "You don't have permission");
            return ResponseEntity.badRequest().body(apiResponse);
        }
        Wordburn wordburn = wordburnRepo.findByIdAndIsActiveTrue(wordburnWinnersRequestDto.getWordburnId());
        if (wordburn == null) {
            ApiResponse apiResponse = new ApiResponse(false, "Wordburn not found");
            return ResponseEntity.ok(apiResponse);
        }
        if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.CANCEL_WORDBURN.toString())) {
            refundCreditsOfComments(wordburn);
            wordburn.setWordburnStatus(WordburnStatus.CANCELLED);
            wordburnRepo.save(wordburn);
            ApiResponse apiResponse = new ApiResponse(true, "Refund Successful!");
            return ResponseEntity.ok(apiResponse);
        }

        Long commentCount = commentRepo.countByWordburn(wordburn);

        Double totalCreditsOfWordburn = commentCount * wordburn.getCreditsPerComment();
        Long numberOfWinningComments = 0L;
        if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.LOLLEEY_STANDARD.toString())) {
            numberOfWinningComments = Math.round(wordburn.getCommentCount() * 0.12);
        } else if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.ALL_WINNERS.toString())) {
            numberOfWinningComments = wordburn.getCommentCount();
        }
        if (numberOfWinningComments != 0) {
            List<BigInteger> likes = commentRepo.getTopDistinctComments(wordburn.getId(), numberOfWinningComments);
            Long noOfWinningLikesOfWordburn = 0L;
            List<Comment> winningComments = new ArrayList<>();
            for (BigInteger noLikes : likes) {
                if (noLikes.longValue() != 0) {
                    List<Comment> commentList = commentRepo.findAllByWordburnAndLikes(wordburn, noLikes.longValue());
                    for (Comment comment :
                            commentList) {
                        noOfWinningLikesOfWordburn += comment.getLikes();
                        winningComments.add(comment);
                    }
                    if (wordburnWinnersRequestDto.getWinnersType().equals(WinnerType.LOLLEEY_STANDARD.toString()) && winningComments.size() >= numberOfWinningComments) {
                        break;
                    }
                }
            }

            if (noOfWinningLikesOfWordburn != 0) {
                Double creditsPerLike = totalCreditsOfWordburn / noOfWinningLikesOfWordburn;
                winningComments.forEach(comment -> {
                    AppUser commentedUser = comment.getCommentedUser();
                    Double winningCredits = Util.getInstance().formatDecimalNumber(comment.getLikes() * creditsPerLike);
                    commentedUser.setCredits(commentedUser.getCredits() + winningCredits);
                    appUserRepo.save(commentedUser);
                    WordburnWinners wordburnWinners = new WordburnWinners(wordburn, comment, winningCredits);
                    wordburnWinnersRepo.save(wordburnWinners);
                    wordburn.setWordburnStatus(WordburnStatus.COMPLETED);
                    wordburnRepo.save(wordburn);
                    String message = "Congrats you won for wordburn " + wordburn.getTopic();
                    notificationService.sendNotification(message, wordburn.getId(), comment.getId(), commentedUser);
                    Notification notification = new Notification();
                    notification.setMessage(Util.getInstance().truncate(message,50));
                    notification.setWordburnId(comment.getWordburn().getId());
                    notification.setCommentId(comment.getId());
                    notification.setAppUser(comment.getCommentedUser());
                    notification.setIsRead(Boolean.FALSE);
                    notificationRepo.save(notification);
                });
                WordburnFeed wordburnFeed = new WordburnFeed();
                wordburnFeed.setWordburnId(wordburn.getId());
                wordburnFeed.setFeedType(FeedType.WORDBURN_WINNERS);
                wordburnFeed.setCommentCount(commentCount);
                wordburnFeed.setTotalWinners((long) winningComments.size());
                wordburnFeed.setTotalCredits(totalCreditsOfWordburn);
                wordburnFeed.setTopic(wordburn.getTopic());
                wordburnFeedRepo.save(wordburnFeed);

                List<Comment> commentList = commentRepo.findAllByWordburnAndIsActiveTrue(wordburn);
                for (Comment comment :
                        commentList) {
                    if (!winningComments.contains(comment)) {
                        String message = "Winners announced for wordburn " + wordburn.getTopic();
                        notificationService.sendNotification(message, wordburn.getId(), comment.getId(), comment.getCommentedUser());
                        Notification notification = new Notification();
                        notification.setMessage(Util.getInstance().truncate(message,50));
                        notification.setWordburnId(comment.getWordburn().getId());
                        notification.setCommentId(comment.getId());
                        notification.setAppUser(comment.getCommentedUser());
                        notification.setIsRead(Boolean.FALSE);
                        notificationRepo.save(notification);
                    }
                }

                ApiResponse apiResponse = new ApiResponse(true, "Successful!");
                return ResponseEntity.ok(apiResponse);
            } else {
                ApiResponse apiResponse = new ApiResponse(false, "No likes for comments");
                return ResponseEntity.ok(apiResponse);
            }
        } else {
            ApiResponse apiResponse = new ApiResponse(false, "No comments found");
            return ResponseEntity.ok(apiResponse);
        }
    }

    @Override
    public ResponseEntity getTodayClosingWordburns(Authentication authentication, PaginationAndSortRequestDto paginationAndSortRequestDto) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (!appUser.getRole().equals(Role.ADMIN)) {
            ApiResponse apiResponse = new ApiResponse(false, "You don't have permission");
            return ResponseEntity.ok(apiResponse);
        }
        Pageable pageable = PageRequest.of(paginationAndSortRequestDto.getRequestPage(), pageItemSize, Sort.Direction.fromString(paginationAndSortRequestDto.getSortOrder()), paginationAndSortRequestDto.getSortBy());
        DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        Date todayFullDate = new Date();
        Date today = null;
        try {
            today = formatter.parse(formatter.format(todayFullDate));
        } catch (ParseException e) {
            Util.LOGGER.error(e.getMessage());
        }

        Page<Wordburn> wordburnPage = wordburnRepo.findAllByResultDateLessThanEqualAndWordburnStatusAndIsActiveTrue(today, WordburnStatus.CLOSED_FOR_COMMENTS, pageable);
        if (wordburnPage.isEmpty()) {
            ApiResponse apiResponse = new ApiResponse(false, "No results found");
            return ResponseEntity.ok(apiResponse);
        }
        List<ClosingWordburnResponseDto> closingWordburnResponseDtoList = new ArrayList<>();
        for (Wordburn wordburn : wordburnPage) {
            ClosingWordburnResponseDto closingWordburnResponseDto = new ClosingWordburnResponseDto();
            closingWordburnResponseDto.setWordburnId(wordburn.getId());
            closingWordburnResponseDto.setTopic(wordburn.getTopic());
            closingWordburnResponseDto.setCommentCount(wordburn.getCommentCount());
            Long commentCount = commentRepo.countByWordburn(wordburn);
            closingWordburnResponseDto.setTotalCredits(wordburn.getCreditsPerComment() * commentCount);
            closingWordburnResponseDtoList.add(closingWordburnResponseDto);
        }
        Map<String, Object> map = new HashMap<>();
        map.put("wordburnList", closingWordburnResponseDtoList);
        map.put("currentPage", wordburnPage.getNumber());
        map.put("totalPages", wordburnPage.getTotalPages());

        ApiResponse apiResponse = new ApiResponse(true, "Successful!", map);
        return ResponseEntity.ok(apiResponse);
    }

    @Override
    public ResponseEntity changeUserStatus(ChangeUserStatusDto changeUserStatusDto, Authentication authentication) {
        AppUser appUser = appUserRepo.findByMobileNumber(authentication.getName());
        if (!appUser.getRole().equals(Role.ADMIN)) {
            ApiResponse apiResponse = new ApiResponse(false, "You don't have permission");
            return ResponseEntity.badRequest().body(apiResponse);
        }
        AppUser user = appUserRepo.getOne(changeUserStatusDto.getId());
        user.setIsActive(changeUserStatusDto.getIsActive());
        appUserRepo.save(user);
        ApiResponse apiResponse = new ApiResponse(true, "Successful!");
        return ResponseEntity.ok(apiResponse);
    }

    private void refundCreditsOfComments(Wordburn wordburn) {
        List<Comment> commentList = commentRepo.findAllByWordburnAndIsActiveTrue(wordburn);
        for (Comment comment :
                commentList) {
            AppUser appUser = comment.getCommentedUser();
            appUser.setCredits(appUser.getCredits() + comment.getCredits());
            appUserRepo.save(appUser);
        }

    }
}
