"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var OtherPrimeInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for OtherPrimeInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OtherPrimeInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OtherPrimeInfo);

		//region Internal properties of the object
		/**
   * @type {Integer}
   * @description prime
   */
		this.prime = (0, _pvutils.getParametersValue)(parameters, "prime", OtherPrimeInfo.defaultValues("prime"));
		/**
   * @type {Integer}
   * @description exponent
   */
		this.exponent = (0, _pvutils.getParametersValue)(parameters, "exponent", OtherPrimeInfo.defaultValues("exponent"));
		/**
   * @type {Integer}
   * @description coefficient
   */
		this.coefficient = (0, _pvutils.getParametersValue)(parameters, "coefficient", OtherPrimeInfo.defaultValues("coefficient"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if ("json" in parameters) this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(OtherPrimeInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OtherPrimeInfo.schema({
				names: {
					prime: "prime",
					exponent: "exponent",
					coefficient: "coefficient"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OtherPrimeInfo");
			//endregion

			//region Get internal properties from parsed schema
			this.prime = asn1.result.prime.convertFromDER();
			this.exponent = asn1.result.exponent.convertFromDER();
			this.coefficient = asn1.result.coefficient.convertFromDER();
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: [this.prime.convertToDER(), this.exponent.convertToDER(), this.coefficient.convertToDER()]
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			return {
				r: (0, _pvutils.toBase64)((0, _pvutils.arrayBufferToString)(this.prime.valueBlock.valueHex), true, true),
				d: (0, _pvutils.toBase64)((0, _pvutils.arrayBufferToString)(this.exponent.valueBlock.valueHex), true, true),
				t: (0, _pvutils.toBase64)((0, _pvutils.arrayBufferToString)(this.coefficient.valueBlock.valueHex), true, true)
			};
		}
		//**********************************************************************************
		/**
   * Convert JSON value into current object
   * @param {Object} json
   */

	}, {
		key: "fromJSON",
		value: function fromJSON(json) {
			if ("r" in json) this.prime = new asn1js.Integer({ valueHex: (0, _pvutils.stringToArrayBuffer)((0, _pvutils.fromBase64)(json.r, true)) });else throw new Error("Absent mandatory parameter \"r\"");

			if ("d" in json) this.exponent = new asn1js.Integer({ valueHex: (0, _pvutils.stringToArrayBuffer)((0, _pvutils.fromBase64)(json.d, true)) });else throw new Error("Absent mandatory parameter \"d\"");

			if ("t" in json) this.coefficient = new asn1js.Integer({ valueHex: (0, _pvutils.stringToArrayBuffer)((0, _pvutils.fromBase64)(json.t, true)) });else throw new Error("Absent mandatory parameter \"t\"");
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "prime":
					return new asn1js.Integer();
				case "exponent":
					return new asn1js.Integer();
				case "coefficient":
					return new asn1js.Integer();
				default:
					throw new Error("Invalid member name for OtherPrimeInfo class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//OtherPrimeInfo ::= Sequence {
			//    prime             Integer,  -- ri
			//    exponent          Integer,  -- di
			//    coefficient       Integer   -- ti
			//}

			/**
    * @type {Object}
    * @property {string} prime
    * @property {string} exponent
    * @property {string} coefficient
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.prime || "" }), new asn1js.Integer({ name: names.exponent || "" }), new asn1js.Integer({ name: names.coefficient || "" })]
			});
		}
	}]);

	return OtherPrimeInfo;
}();
//**************************************************************************************


exports.default = OtherPrimeInfo;
//# sourceMappingURL=OtherPrimeInfo.js.map