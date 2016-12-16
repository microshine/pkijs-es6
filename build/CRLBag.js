"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _CertificateRevocationList = require("./CertificateRevocationList");

var _CertificateRevocationList2 = _interopRequireDefault(_CertificateRevocationList);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var CRLBag = function () {
	//**********************************************************************************
	/**
  * Constructor for CRLBag class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CRLBag() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CRLBag);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description crlId
   */
		this.crlId = (0, _pvutils.getParametersValue)(parameters, "crlId", CRLBag.defaultValues("crlId"));
		/**
   * @type {*}
   * @description crlValue
   */
		this.crlValue = (0, _pvutils.getParametersValue)(parameters, "crlValue", CRLBag.defaultValues("crlValue"));

		if ("parsedValue" in parameters) {
			/**
    * @type {*}
    * @description parsedValue
    */
			this.parsedValue = (0, _pvutils.getParametersValue)(parameters, "parsedValue", CRLBag.defaultValues("parsedValue"));
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


	_createClass(CRLBag, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CRLBag.schema({
				names: {
					id: "crlId",
					value: "crlValue"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CRLBag");
			//endregion

			//region Get internal properties from parsed schema
			this.crlId = asn1.result.crlId.valueBlock.toString();
			this.crlValue = asn1.result.crlValue;

			switch (this.crlId) {
				case "1.2.840.113549.1.9.23.1":
					// x509CRL
					{
						var _asn = asn1js.fromBER(this.certValue.valueBlock.valueHex);
						this.parsedValue = new _CertificateRevocationList2.default({ schema: _asn.result });
					}
					break;
				default:
					throw new Error("Incorrect \"crlId\" value in CertBag: " + this.crlId);
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
				this.certId = "1.2.840.113549.1.9.23.1";
				this.certValue = new asn1js.OctetString({ valueHex: this.parsedValue.toSchema().toBER(false) });
			}

			return new asn1js.Sequence({
				value: [new asn1js.ObjectIdentifier({ value: this.crlId }), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [this.crlValue.toSchema()]
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
				crlId: this.crlId,
				crlValue: this.crlValue.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "crlId":
					return "";
				case "crlValue":
					return new asn1js.Any();
				case "parsedValue":
					return {};
				default:
					throw new Error("Invalid member name for CRLBag class: " + memberName);
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
				case "crlId":
					return memberValue === "";
				case "crlValue":
					return memberValue instanceof asn1js.Any;
				case "parsedValue":
					return memberValue instanceof Object && Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for CRLBag class: " + memberName);
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

			//CRLBag ::= SEQUENCE {
			//    crlId     	BAG-TYPE.&id ({CRLTypes}),
			//    crlValue 	[0] EXPLICIT BAG-TYPE.&Type ({CRLTypes}{@crlId})
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

	return CRLBag;
}();
//**************************************************************************************


exports.default = CRLBag;
//# sourceMappingURL=CRLBag.js.map