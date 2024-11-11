
import React, { useCallback, useEffect, useRef, useState } from "react";

import DarkMode from "./DarkMode";

const NODE_MODE = process.env.NODE_ENV;
const Main = () => {
	
	const ref = useRef<HTMLDivElement>(null);
	const [ height, setHeight ] = useState<number>(0);

	/** 첫 번째 h1 요소의 높이를 가져와서 div의 높이로 설정 */
	const updateHeight = useCallback(() => {
		if(ref.current && ref.current.children[0])
			setHeight(ref.current.children[0].getBoundingClientRect().height);
	}, []);

	/** 페이지 로드, 창 크기 조정 시 높이 업데이트 */
	useEffect(() => {

		updateHeight();

		window.addEventListener(`resize`, updateHeight);
		return () => window.removeEventListener(`resize`, updateHeight);

	}, []);

	return (
	<div className={`main-wrap`}>
		<div className={`main-box`}>
			<div ref={ref} className={`title`} style={{
				height: `${height}px`
			}}>
				<h1>{`St2lla Authentication Server`}</h1>
				<h1>{`St2lla Authentication Server`}</h1>
				<h1>{`St2lla Authentication Server`}</h1>
				<h1>{`St2lla Authentication Server`}</h1>
			</div>
			<div className={`info`}>
				<span>{`인증 요청은 지정된 양식에 따라 진행해 주시고, 관련 내용은 문의 부탁드립니다.`}</span>
			</div>
		</div>
		{NODE_MODE && <DarkMode mode={NODE_MODE} />}
	</div>
	);

};

export default React.memo(Main);