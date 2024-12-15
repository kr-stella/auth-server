import classNames from "classnames";
import React, { useEffect, useCallback, useState } from "react";

export type Environment = `development`|`deployment`|`production`;
export type CookieDomain = {[key in Environment]:string;};
export const COOKIE_DOMAIN:CookieDomain = {
	development: `localhost`,
	deployment: `.dev.st2lla.co.kr`,
	production: `.intra.st2lla.co.kr`
};
/** isDark 쿠키를 설정하는 함수 */
const setCookie = (domain:string, name:string, value:string, days:number):void => {
	const secure = window.location.protocol === `https:`? `; Secure`:``;
	document.cookie = `${name}=${value}; expires=${new Date(Date.now() + days * 864e5).toUTCString()}; path=/; domain=${domain}; SameSite=Lax${secure}`;
};

/** isDark 쿠키를 호출하는 함수 */
const getCookie = (name:string):string|undefined => {

	const value = `; ${document.cookie}`;
	const parts = value.split(`; ${name}=`);
	if(parts.length === 2) {

		const part = parts.pop();
		if(part)
			return part.split(`;`).shift();

	}

	return undefined;

};

interface Define {mode:string;};

/** 문서의 최상단 요소 ( html ) */
const html = document.documentElement;
const DarkMode = ({ mode }:Define) => {

	const [ isDarkMode, setDarkMode ] = useState(getCookie(`theme`) === `dark`);
	
	/** 다크모드 Toggle */
	const onDarkMode = useCallback(():void => {

		const isDark = !isDarkMode;
		const domain = COOKIE_DOMAIN[mode];
		setDarkMode(isDark);
		/** 설정 Toggle */
		if(isDark) {
			html.setAttribute(`theme`, `dark`);
			setCookie(domain, `theme`, `dark`, 365);
		} else {
			html.removeAttribute(`theme`);
			setCookie(domain, `theme`, ``, -1);
		}

	}, [isDarkMode, mode]);
	
	/** 페이지 마운트 시 localStorage여부로 최초 1회 다크모드 설정 */
	useEffect(() => {
		if(getCookie(`theme`) === `dark`) {
			html.setAttribute(`theme`, `dark`);
			setCookie(COOKIE_DOMAIN[mode], `theme`, `dark`, 365);
		} else html.removeAttribute(`theme`);
	}, []);

	return (
	<div className={classNames(`icon`, isDarkMode && `on`)} onClick={onDarkMode}>
		<svg xmlns={`http://www.w3.org/2000/svg`} xmlnsXlink={`http://www.w3.org/1999/xlink`} xmlSpace={`preserve`} version={`1.1`} width={256} height={256} viewBox={`0 0 256 256`}>
			<defs />
			<g transform={`translate(128 128) scale(0.72 0.72)`}>
				<g transform={`translate(-175.05 -175.05000000000004) scale(3.89 3.89)`} style={{
					stroke: `none`, strokeWidth: 0, strokeDasharray: `none`, strokeLinecap: `butt`, strokeLinejoin: `miter`, strokeMiterlimit: 10,
					fill: `none`, fillRule: `nonzero`, opacity: 1
				}}>
					<path transform={`matrix(1 0 0 1 0 0)`} strokeLinecap={`round`} d={`M 89.634 59.683 c -0.338 -0.276 -0.816 -0.302 -1.184 -0.062 c -16.514 10.864 -38.661 8.589 -52.661 -5.41 C 21.79 40.212 19.515 18.065 30.38 1.551 c 0.24 -0.366 0.215 -0.845 -0.062 -1.183 c -0.277 -0.339 -0.741 -0.46 -1.148 -0.294 c -5.826 2.349 -11.048 5.809 -15.523 10.283 c -18.195 18.195 -18.195 47.802 0 65.997 C 22.744 85.451 34.695 90 46.645 90 c 11.951 0 23.901 -4.549 32.999 -13.646 c 4.475 -4.476 7.935 -9.699 10.284 -15.523 C 90.091 60.425 89.972 59.96 89.634 59.683 z`}
						style={{
							stroke: `none`, strokeWidth: 1, strokeDasharray: `none`, strokeLinecap: `butt`, strokeLinejoin: `miter`, strokeMiterlimit: 10,
							fill: `white`, fillRule: `nonzero`, opacity: 1
						}} />
					<path transform={`matrix(1 0 0 1 0 0)`} strokeLinecap={`round`} d={`M 77.254 40.17 c -4.894 -1.63 -8.788 -5.525 -10.42 -10.419 c -0.27 -0.81 -0.992 -1.334 -1.841 -1.334 c -0.848 0 -1.571 0.524 -1.84 1.335 c -1.631 4.893 -5.526 8.787 -10.419 10.418 c -0.811 0.27 -1.334 0.993 -1.334 1.841 c 0 0.848 0.524 1.571 1.334 1.841 c 4.894 1.631 8.788 5.525 10.418 10.419 h 0.001 c 0.27 0.811 0.992 1.334 1.84 1.334 c 0.849 0 1.572 -0.524 1.841 -1.334 c 1.631 -4.893 5.526 -8.788 10.419 -10.419 c 0.812 -0.27 1.335 -0.992 1.335 -1.841 C 78.588 41.162 78.064 40.439 77.254 40.17 z`}
						style={{
							stroke: `none`, strokeWidth: 1, strokeDasharray: `none`, strokeLinecap: `butt`, strokeLinejoin: `miter`, strokeMiterlimit: 10,
							fill: `white`, fillRule: `nonzero`, opacity: 1
						}} />
					<path transform={`matrix(1 0 0 1 0 0)`} strokeLinecap={`round`} d={`M 81.635 11.577 c -2.597 -0.865 -4.664 -2.932 -5.53 -5.529 c -0.208 -0.626 -0.789 -1.046 -1.446 -1.046 c -0.657 0 -1.239 0.421 -1.448 1.047 c -0.864 2.596 -2.93 4.663 -5.527 5.528 c -0.626 0.208 -1.047 0.789 -1.047 1.446 s 0.421 1.238 1.046 1.446 c 2.596 0.865 4.663 2.932 5.529 5.529 c 0.208 0.625 0.788 1.046 1.445 1.047 c 0.001 0 0.001 0 0.002 0 c 0.656 0 1.238 -0.421 1.446 -1.046 c 0.866 -2.597 2.933 -4.664 5.53 -5.529 c 0.625 -0.209 1.046 -0.79 1.046 -1.446 C 82.681 12.367 82.26 11.786 81.635 11.577 z`}
						style={{
							stroke: `none`, strokeWidth: 1, strokeDasharray: `none`, strokeLinecap: `butt`, strokeLinejoin: `miter`, strokeMiterlimit: 10,
							fill: `white`, fillRule: `nonzero`, opacity: 1
						}} />
					<path transform={`matrix(1 0 0 1 0 0)`} strokeLinecap={`round`} d={`M 52.274 18.689 c -3.232 -1.076 -5.805 -3.649 -6.882 -6.881 c -0.224 -0.674 -0.849 -1.126 -1.556 -1.126 c -0.706 0 -1.331 0.453 -1.556 1.126 c -1.077 3.232 -3.649 5.804 -6.881 6.881 c -0.674 0.224 -1.126 0.849 -1.126 1.556 s 0.453 1.331 1.126 1.556 c 3.232 1.077 5.805 3.65 6.881 6.882 c 0.224 0.674 0.849 1.126 1.556 1.126 c 0.706 0 1.331 -0.453 1.556 -1.126 c 1.077 -3.232 3.649 -5.805 6.881 -6.882 c 0.674 -0.224 1.127 -0.849 1.127 -1.556 S 52.947 18.913 52.274 18.689 z`}
						style={{
							stroke: `none`, strokeWidth: 1, strokeDasharray: `none`, strokeLinecap: `butt`, strokeLinejoin: `miter`, strokeMiterlimit: 10,
							fill: `white`, fillRule: `nonzero`, opacity: 1
						}} />
				</g>
			</g>
		</svg>
	</div>
	);

};

export default React.memo(DarkMode);