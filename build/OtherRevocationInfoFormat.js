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

var OtherRevocationInfoFormat = function () {
	//**********************************************************************************
	/**
  * Constructor for OtherRevocationInfoFormat class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OtherRevocationInfoFormat() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OtherRevocationInfoFormat);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description otherRevInfoFormat
   */
		this.otherRevInfoFormat = (0, _pvutils.getParametersValue)(parameters, "otherRevInfoFormat", OtherRevocationInfoFormat.defaultValues("otherRevInfoFormat"));
		/**
   * @type {Any}
   * @description otherRevInfo
   */
		this.otherRevInfo = (0, _pvutils.getParametersValue)(parameters, "otherRevInfo", OtherRevocationInfoFormat.defaultValues("otherRevInfo"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(OtherRevocationInfoFormat, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OtherRevocationInfoFormat.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OtherRevocationInfoFormat");
			//endregion

			//region Get internal properties from parsed schema
			this.otherRevInfoFormat = asn1.result.otherRevInfoFormat.valueBlock.toString();
			this.otherRevInfo = asn1.result.otherRevInfo;
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
				value: [new asn1js.ObjectIdentifier({ value: this.otherRevInfoFormat }), this.otherRevInfo]
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
			var object = {
				otherRevInfoFormat: this.otherRevInfoFormat
			};

			if (!(this.otherRevInfo instanceof asn1js.Any)) object.otherRevInfo = this.otherRevInfo.toJSON();

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "otherRevInfoFormat":
					return "";
				case "otherRevInfo":
					return new asn1js.Any();
				default:
					throw new Error("Invalid member name for OtherRevocationInfoFormat class: " + memberName);
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

			//OtherCertificateFormat ::= SEQUENCE {
			//    otherRevInfoFormat OBJECT IDENTIFIER,
			//    otherRevInfo ANY DEFINED BY otherCertFormat }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [otherRevInfoFormat]
    * @property {string} [otherRevInfo]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.otherRevInfoFormat || "otherRevInfoFormat" }), new asn1js.Any({ name: names.otherRevInfo || "otherRevInfo" })]
			});
		}
	}]);

	return OtherRevocationInfoFormat;
}();
//**************************************************************************************


exports.default = OtherRevocationInfoFormat;
//# sourceMappingURL=OtherRevocationInfoFormat.js.map