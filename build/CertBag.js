"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _Certificate = require("./Certificate");

var _Certificate2 = _interopRequireDefault(_Certificate);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var CertBag = function () {
	//**********************************************************************************
	/**
  * Constructor for CertBag class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertBag() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertBag);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description certId
   */
		this.certId = (0, _pvutils.getParametersValue)(parameters, "certId", CertBag.defaultValues("certId"));
		/**
   * @type {*}
   * @description certValue
   */
		this.certValue = (0, _pvutils.getParametersValue)(parameters, "certValue", CertBag.defaultValues("certValue"));

		if ("parsedValue" in parameters) {
			/**
    * @type {*}
    * @description parsedValue
    */
			this.parsedValue = (0, _pvutils.getParametersValue)(parameters, "parsedValue", CertBag.defaultValues("parsedValue"));
		}
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


	_createClass(CertBag, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CertBag.schema({
				names: {
					id: "certId",
					value: "certValue"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CertBag");
			//endregion

			//region Get internal properties from parsed schema
			this.certId = asn1.result.certId.valueBlock.toString();
			this.certValue = asn1.result.certValue;

			switch (this.certId) {
				case "1.2.840.113549.1.9.22.1":
					// x509Certificate
					{
						var _asn = asn1js.fromBER(this.certValue.valueBlock.valueHex);
						this.parsedValue = new _Certificate2.default({ schema: _asn.result });
					}
					break;
				case "1.2.840.113549.1.9.22.2": // sdsiCertificate
				default:
					throw new Error("Incorrect \"certId\" value in CertBag: " + this.certId);
			}
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
			if ("parsedValue" in this) {
				this.certId = "1.2.840.113549.1.9.22.1";
				this.certValue = new asn1js.OctetString({ valueHex: this.parsedValue.toSchema().toBER(false) });
			}

			return new asn1js.Sequence({
				value: [new asn1js.ObjectIdentifier({ value: this.certId }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: ["toSchema" in this.certValue ? this.certValue.toSchema() : this.certValue]
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
				certId: this.certId,
				certValue: this.certValue.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "certId":
					return "";
				case "certValue":
					return new asn1js.Any();
				case "parsedValue":
					return {};
				default:
					throw new Error("Invalid member name for CertBag class: " + memberName);
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
				case "certId":
					return memberValue === "";
				case "certValue":
					return memberValue instanceof asn1js.Any;
				case "parsedValue":
					return memberValue instanceof Object && Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for CertBag class: " + memberName);
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

			//CertBag ::= SEQUENCE {
			//    certId    BAG-TYPE.&id   ({CertTypes}),
			//    certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [id]
    * @property {string} [value]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.id || "id" }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Any({ name: names.value || "value" })] // EXPLICIT ANY value
				})]
			});
		}
	}]);

	return CertBag;
}();
//**************************************************************************************


exports.default = CertBag;
//# sourceMappingURL=CertBag.js.map