package com.pma.projectmanagement.controller;

import com.pma.projectmanagement.dao.UserAccountRepository;
import com.pma.projectmanagement.entities.UserAccount;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class SecurityController {

    @Autowired
    BCryptPasswordEncoder bCryptEncoder;

    @Autowired
    UserAccountRepository userAccountRepository;

    @GetMapping("/register")
    public String register(Model model){

        UserAccount userAccount = new UserAccount();

        model.addAttribute("userAccount", userAccount);

        return "security/register";
    }

    @PostMapping("/register/save")
    public String saveUSer(Model model, UserAccount user){

        user.setPassword(bCryptEncoder.encode(user.getPassword()));

        userAccountRepository.save(user);

        return "redirect:/";


    }

//    @GetMapping("/login")
//    public String login() {
//        return "security/login";
//    }

}