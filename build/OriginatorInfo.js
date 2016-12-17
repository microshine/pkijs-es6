"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _CertificateSet = require("./CertificateSet");

var _CertificateSet2 = _interopRequireDefault(_CertificateSet);

var _RevocationInfoChoices = require("./RevocationInfoChoices");

var _RevocationInfoChoices2 = _interopRequireDefault(_RevocationInfoChoices);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var OriginatorInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for OriginatorInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OriginatorInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OriginatorInfo);

		//region Internal properties of the object
		/**
   * @type {CertificateSet}
   * @description certs
   */
		this.certs = (0, _pvutils.getParametersValue)(parameters, "certs", OriginatorInfo.defaultValues("certs"));
		/**
   * @type {RevocationInfoChoices}
   * @description crls
   */
		this.crls = (0, _pvutils.getParametersValue)(parameters, "crls", OriginatorInfo.defaultValues("crls"));
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


	_createClass(OriginatorInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OriginatorInfo.schema({
				names: {
					certs: "certs",
					crls: "crls"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OriginatorInfo");
			//endregion

			//region Get internal properties from parsed schema
			asn1.result.certs.idBlock.tagClass = 1; // UNIVERSAL
			asn1.result.certs.idBlock.tagNumber = 17; // SET

			this.certs = new _CertificateSet2.default({ schema: asn1.result.certs });

			asn1.result.crls.idBlock.tagClass = 1; // UNIVERSAL
			asn1.result.crls.idBlock.tagNumber = 17; // SET

			this.crls = new _RevocationInfoChoices2.default({ schema: asn1.result.crls });
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
				value: [new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: this.certs.toSchema().valueBlock.value
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: this.crls.toSchema().valueBlock.value
				})]
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
				certs: this.certs.toJSON(),
				crls: this.crls.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "certs":
					return new _CertificateSet2.default();
				case "crls":
					return new _RevocationInfoChoices2.default();
				default:
					throw new Error("Invalid member name for OriginatorInfo class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "certs":
					return memberValue.certificates.length === 0;
				case "crls":
					return memberValue.crls.length === 0 && memberValue.otherRevocationInfos.length === 0;
				default:
					throw new Error("Invalid member name for OriginatorInfo class: " + memberName);
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

			//OriginatorInfo ::= SEQUENCE {
			//    certs [0] IMPLICIT CertificateSet OPTIONAL,
			//    crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [certs]
    * @property {string} [crls]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Constructed({
					name: names.certs || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: _CertificateSet2.default.schema().valueBlock.value
				}), new asn1js.Constructed({
					name: names.crls || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: _RevocationInfoChoices2.default.schema().valueBlock.value
				})]
			});
		}
	}]);

	return OriginatorInfo;
}();
//**************************************************************************************


exports.default = OriginatorInfo;
//# sourceMappingURL=OriginatorInfo.js.map