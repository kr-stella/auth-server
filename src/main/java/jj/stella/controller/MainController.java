package jj.stella.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class MainController {
	
	/** 메인페이지 - 검증서버 활용방법에 대한 안내 등 */
	@GetMapping(value={"/"})
	public ModelAndView main(HttpServletRequest req) throws Exception {
		
		ModelAndView page = new ModelAndView();
		page.setViewName("index");
		
		return page;
		
	};
	
}