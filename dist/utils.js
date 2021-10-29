"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.replaceDerive = exports.pathRegex = void 0;
exports.pathRegex = new RegExp("^m(\\/[0-9]+')+$");
const replaceDerive = (val) => val.replace("'", '');
exports.replaceDerive = replaceDerive;
