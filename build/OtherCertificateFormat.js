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

var OtherCertificateFormat = function () {
	//**********************************************************************************
	/**
  * Constructor for OtherCertificateFormat class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OtherCertificateFormat() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OtherCertificateFormat);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description otherCertFormat
   */
		this.otherCertFormat = (0, _pvutils.getParametersValue)(parameters, "otherCertFormat", OtherCertificateFormat.defaultValues("otherCertFormat"));
		/**
   * @type {Any}
   * @description otherCert
   */
		this.otherCert = (0, _pvutils.getParametersValue)(parameters, "otherCert", OtherCertificateFormat.defaultValues("otherCert"));
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


	_createClass(OtherCertificateFormat, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OtherCertificateFormat.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OtherCertificateFormat");
			//endregion

			//region Get internal properties from parsed schema
			this.otherCertFormat = asn1.result.otherCertFormat.valueBlock.toString();
			this.otherCert = asn1.result.otherCert;
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
				value: [new asn1js.ObjectIdentifier({ value: this.otherCertFormat }), this.otherCert]
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
				otherCertFormat: this.otherCertFormat
			};

			if (!(this.otherCert instanceof asn1js.Any)) object.otherCert = this.otherCert.toJSON();

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "otherCertFormat":
					return "";
				case "otherCert":
					return new asn1js.Any();
				default:
					throw new Error("Invalid member name for OtherCertificateFormat class: " + memberName);
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
			//    otherCertFormat OBJECT IDENTIFIER,
			//    otherCert ANY DEFINED BY otherCertFormat }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [otherCertFormat]
    * @property {string} [otherCert]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.otherCertFormat || "otherCertFormat" }), new asn1js.Any({ name: names.otherCert || "otherCert" })]
			});
		}
	}]);

	return OtherCertificateFormat;
}();
//**************************************************************************************


exports.default = OtherCertificateFormat;
//# sourceMappingURL=OtherCertificateFormat.js.map