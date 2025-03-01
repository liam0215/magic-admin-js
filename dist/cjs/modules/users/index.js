"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var base_module_1 = require("../base-module");
var sdk_exceptions_1 = require("../../core/sdk-exceptions");
var rest_1 = require("../../utils/rest");
var issuer_1 = require("../../utils/issuer");
var UsersModule = /** @class */ (function (_super) {
    __extends(UsersModule, _super);
    function UsersModule() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    // --- User logout endpoints
    UsersModule.prototype.logoutByIssuer = function (issuer) {
        return __awaiter(this, void 0, void 0, function () {
            var body;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!this.sdk.secretApiKey)
                            throw sdk_exceptions_1.createApiKeyMissingError();
                        body = { issuer: issuer };
                        return [4 /*yield*/, rest_1.post(this.sdk.apiBaseUrl + "/v2/admin/auth/user/logout", this.sdk.secretApiKey, body)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    UsersModule.prototype.logoutByPublicAddress = function (publicAddress) {
        return __awaiter(this, void 0, void 0, function () {
            var issuer;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        issuer = issuer_1.generateIssuerFromPublicAddress(publicAddress);
                        return [4 /*yield*/, this.logoutByIssuer(issuer)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    UsersModule.prototype.logoutByToken = function (DIDToken) {
        return __awaiter(this, void 0, void 0, function () {
            var issuer;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        issuer = this.sdk.token.getIssuer(DIDToken);
                        return [4 /*yield*/, this.logoutByIssuer(issuer)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    // --- User metadata endpoints
    UsersModule.prototype.getMetadataByIssuer = function (issuer) {
        var _a, _b, _c, _d, _e;
        return __awaiter(this, void 0, void 0, function () {
            var data;
            return __generator(this, function (_f) {
                switch (_f.label) {
                    case 0:
                        if (!this.sdk.secretApiKey)
                            throw sdk_exceptions_1.createApiKeyMissingError();
                        return [4 /*yield*/, rest_1.get(this.sdk.apiBaseUrl + "/v1/admin/auth/user/get", this.sdk.secretApiKey, { issuer: issuer })];
                    case 1:
                        data = _f.sent();
                        return [2 /*return*/, {
                                issuer: (_a = data.issuer) !== null && _a !== void 0 ? _a : null,
                                publicAddress: (_b = data.public_address) !== null && _b !== void 0 ? _b : null,
                                email: (_c = data.email) !== null && _c !== void 0 ? _c : null,
                                oauthProvider: (_d = data.oauth_provider) !== null && _d !== void 0 ? _d : null,
                                phoneNumber: (_e = data.phone_number) !== null && _e !== void 0 ? _e : null,
                            }];
                }
            });
        });
    };
    UsersModule.prototype.getMetadataByToken = function (DIDToken) {
        return __awaiter(this, void 0, void 0, function () {
            var issuer;
            return __generator(this, function (_a) {
                issuer = this.sdk.token.getIssuer(DIDToken);
                return [2 /*return*/, this.getMetadataByIssuer(issuer)];
            });
        });
    };
    UsersModule.prototype.getMetadataByPublicAddress = function (publicAddress) {
        return __awaiter(this, void 0, void 0, function () {
            var issuer;
            return __generator(this, function (_a) {
                issuer = issuer_1.generateIssuerFromPublicAddress(publicAddress);
                return [2 /*return*/, this.getMetadataByIssuer(issuer)];
            });
        });
    };
    return UsersModule;
}(base_module_1.BaseModule));
exports.UsersModule = UsersModule;
//# sourceMappingURL=index.js.map