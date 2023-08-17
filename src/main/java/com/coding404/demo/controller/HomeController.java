package com.coding404.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.coding404.demo.command.UserVO;
import com.coding404.demo.user.MyUserDetails;
import com.coding404.demo.user.UserMapper;

@Controller
public class HomeController {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserMapper userMapper;
	
	
	//홈
	@GetMapping("/hello")
	public String hello(Authentication auth) {
		
		//1st - 컨트롤러 매개변수에 Authentication 객체를 선언합니다
		if(auth != null) {
			//System.out.println(auth);
		}
		
		//MyUserDetails details = (MyUserDetails)auth.getPrincipal();			
//		System.out.println(details.getUsername());
//		System.out.println(details.getPassword());
//		System.out.println(details.getRole());
		
		//2nd - 시큐리티세션을 직접사용
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		if( authentication.getPrincipal() instanceof MyUserDetails ) {
			MyUserDetails details = (MyUserDetails)authentication.getPrincipal();
			System.out.println(details);
		}
		
		return "hello";
	}
	
	//회원가입
	@GetMapping("/join")
	public String join() {
		return "join";
	}
	
	//회원가입 요청
	@PostMapping("/joinForm")
	public String joinForm(UserVO vo) {
		
		//서비스영역 생략 > 원래는 만들어줘야 함
		
		//비밀번호 암호화
		String pw = bCryptPasswordEncoder.encode(vo.getPassword());
		vo.setPassword(pw);
		
		//회원가입 작업
		userMapper.join(vo);
		
		return "redirect:/login"; //로그인 페이지로
	}
	
	//커스터마이징 로그인페이지
	@GetMapping("/login")
	public String login(@RequestParam(value="err", required=false) String err,
						Model model) {
	
		if(err != null) {
			model.addAttribute("msg", "아이디와 비밀번호를 확인하세요");
		}
		
		return "login";
	}

	@GetMapping("/all")
	public String all() {
		return "all";
	}

	@GetMapping("/admin/mypage")
	public @ResponseBody String mypage() {
		return "Rest API admin 마이페이지";
	}

	@GetMapping("/user/mypage")
	public @ResponseBody String usermypage() {
		return "Rest API user 마이페이지";
	}
	
	@GetMapping("/deny")
	public @ResponseBody String deny() {
		return "페이지에 접근할 권한이 없습니다";
	}
	
	//admin 권한이 있어야 접근이 가능
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping("/test")
	public @ResponseBody String test() {
		return "여기는 preAuthorize로 처리";
	}
	
}
