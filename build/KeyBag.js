"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _PrivateKeyInfo2 = require("./PrivateKeyInfo");

var _PrivateKeyInfo3 = _interopRequireDefault(_PrivateKeyInfo2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

//**************************************************************************************

var KeyBag = function (_PrivateKeyInfo) {
	_inherits(KeyBag, _PrivateKeyInfo);

	//**********************************************************************************
	/**
  * Constructor for Attribute class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function KeyBag() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, KeyBag);

		return _possibleConstructorReturn(this, (KeyBag.__proto__ || Object.getPrototypeOf(KeyBag)).call(this, parameters));
	}
	//**********************************************************************************


	return KeyBag;
}(_PrivateKeyInfo3.default);
//**************************************************************************************


exports.default = KeyBag;
//# sourceMappingURL=KeyBag.js.map