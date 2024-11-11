import "react-app-polyfill/ie11";
import "react-app-polyfill/stable";
import "../style/main.scss";
// FontAwesome
import "@fortawesome/fontawesome-pro/css/all.min.css";

import React from "react";
import * as ReactDOM from "react-dom/client";

import Main from "./Main";

console.log(`
  /$$$$$$  /$$   /$$ /$$      /$$ /$$$$$$ /$$   /$$
 /$$__  $$| $$  | $$| $$$    /$$$|_  $$_/| $$$ | $$
| $$  \\__/| $$  | $$| $$$$  /$$$$  | $$  | $$$$| $$
|  $$$$$$ | $$  | $$| $$ $$/$$ $$  | $$  | $$ $$ $$
 \\____  $$| $$  | $$| $$  $$$| $$  | $$  | $$  $$$$
 /$$  \\ $$| $$  | $$| $$\\  $ | $$  | $$  | $$\\  $$$
|  $$$$$$/|  $$$$$$/| $$ \\/  | $$ /$$$$$$| $$ \\  $$
 \\______/  \\______/ |__/     |__/|______/|__/  \\__/

`);

console.log(
'%c                                                                        ,,\n' +
'                                                                       /  ,\n' +
'                                                                      /   /\n' +
'                                                                     /   /\n' +
'                                                                    /   /\n' +
'    ___________________________                                    /   /\n' +
'    ⎢                         ⎥                                   /   /\n' +
'    ⎢       안녕하세요 ♥       ⎥                                  /   /\n' +
'    ⎢____    _________________⎥                                 /   /\n' +
'          \\/    ,      ,,                                      /   /\n' +
'               /%c@%c\\____/%c@%c \\                                ____/   /\n' +
'              /           \\                         _____/        /__\n' +
'        /" \\ / •    •      \\                     __/             /  %c@@%c"\\\n' +
'        \\    %c@@%c  ㅅ  %c@@%c     /___             ___/                /    _/\n' +
'       /" \\   \\                 \\__________/                    |__/ "\\\n' +
'       \\   \\                                                   /      /\n' +
'        \\    \\  __                                                  _/\n' +
'         \\                                                       __/\n' +
'           \\_                                             ______/\n' +
'              \\ ___                                    __/\n' +
'                    \\__                             __/\n' +
'                        \\_____                _____/\n' +
'                              \\______________/\n',
	"font-weight: bold;",
	"font-weight: bold; color: #ff7777",
	"font-weight: bold;",
	"font-weight: bold; color: #ff7777",
	"font-weight: bold;",
	"font-weight: bold; color: #ff7777",
	"font-weight: bold;",
	"font-weight: bold; color: #ff7777",
	"font-weight: bold;",
	"font-weight: bold; color: #ff7777",
	"font-weight: bold;"
);

console.log('>> %chttps://st2lla.co.kr', "font-family:story; font-weight: bold;");

const root = ReactDOM.createRoot(document.getElementById(`root`) as HTMLElement);
root.render(
	<Main />
);