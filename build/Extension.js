"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _SubjectDirectoryAttributes = require("./SubjectDirectoryAttributes");

var _SubjectDirectoryAttributes2 = _interopRequireDefault(_SubjectDirectoryAttributes);

var _PrivateKeyUsagePeriod = require("./PrivateKeyUsagePeriod");

var _PrivateKeyUsagePeriod2 = _interopRequireDefault(_PrivateKeyUsagePeriod);

var _AltName = require("./AltName");

var _AltName2 = _interopRequireDefault(_AltName);

var _BasicConstraints = require("./BasicConstraints");

var _BasicConstraints2 = _interopRequireDefault(_BasicConstraints);

var _IssuingDistributionPoint = require("./IssuingDistributionPoint");

var _IssuingDistributionPoint2 = _interopRequireDefault(_IssuingDistributionPoint);

var _GeneralNames = require("./GeneralNames");

var _GeneralNames2 = _interopRequireDefault(_GeneralNames);

var _NameConstraints = require("./NameConstraints");

var _NameConstraints2 = _interopRequireDefault(_NameConstraints);

var _CRLDistributionPoints = require("./CRLDistributionPoints");

var _CRLDistributionPoints2 = _interopRequireDefault(_CRLDistributionPoints);

var _CertificatePolicies = require("./CertificatePolicies");

var _CertificatePolicies2 = _interopRequireDefault(_CertificatePolicies);

var _PolicyMappings = require("./PolicyMappings");

var _PolicyMappings2 = _interopRequireDefault(_PolicyMappings);

var _AuthorityKeyIdentifier = require("./AuthorityKeyIdentifier");

var _AuthorityKeyIdentifier2 = _interopRequireDefault(_AuthorityKeyIdentifier);

var _PolicyConstraints = require("./PolicyConstraints");

var _PolicyConstraints2 = _interopRequireDefault(_PolicyConstraints);

var _ExtKeyUsage = require("./ExtKeyUsage");

var _ExtKeyUsage2 = _interopRequireDefault(_ExtKeyUsage);

var _InfoAccess = require("./InfoAccess");

var _InfoAccess2 = _interopRequireDefault(_InfoAccess);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var Extension = function () {
	//**********************************************************************************
	/**
  * Constructor for Extension class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function Extension() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, Extension);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description extnID
   */
		this.extnID = (0, _pvutils.getParametersValue)(parameters, "extnID", Extension.defaultValues("extnID"));
		/**
   * @type {boolean}
   * @description critical
   */
		this.critical = (0, _pvutils.getParametersValue)(parameters, "critical", Extension.defaultValues("critical"));
		/**
   * @type {OctetString}
   * @description extnValue
   */
		if ("extnValue" in parameters) this.extnValue = new asn1js.OctetString({ valueHex: parameters.extnValue });else this.extnValue = Extension.defaultValues("extnValue");

		if ("parsedValue" in parameters)
			/**
    * @type {Object}
    * @description parsedValue
    */
			this.parsedValue = (0, _pvutils.getParametersValue)(parameters, "parsedValue", Extension.defaultValues("parsedValue"));
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


	_createClass(Extension, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, Extension.schema({
				names: {
					extnID: "extnID",
					critical: "critical",
					extnValue: "extnValue"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for EXTENSION");
			//endregion

			//region Get internal properties from parsed schema
			this.extnID = asn1.result.extnID.valueBlock.toString();
			if ("critical" in asn1.result) this.critical = asn1.result.critical.valueBlock.value;
			this.extnValue = asn1.result.extnValue;

			//region Get "parsedValue" for well-known extensions
			asn1 = asn1js.fromBER(this.extnValue.valueBlock.valueHex);
			if (asn1.offset === -1) return;

			switch (this.extnID) {
				case "2.5.29.9":
					// SubjectDirectoryAttributes
					this.parsedValue = new _SubjectDirectoryAttributes2.default({ schema: asn1.result });
					break;
				case "2.5.29.14":
					// SubjectKeyIdentifier
					this.parsedValue = asn1.result; // Should be just a simple OCTETSTRING
					break;
				case "2.5.29.15":
					// KeyUsage
					this.parsedValue = asn1.result; // Should be just a simple BITSTRING
					break;
				case "2.5.29.16":
					// PrivateKeyUsagePeriod
					this.parsedValue = new _PrivateKeyUsagePeriod2.default({ schema: asn1.result });
					break;
				case "2.5.29.17": // SubjectAltName
				case "2.5.29.18":
					// IssuerAltName
					this.parsedValue = new _AltName2.default({ schema: asn1.result });
					break;
				case "2.5.29.19":
					// BasicConstraints
					this.parsedValue = new _BasicConstraints2.default({ schema: asn1.result });
					break;
				case "2.5.29.20": // CRLNumber
				case "2.5.29.27":
					// BaseCRLNumber (delta CRL indicator)
					this.parsedValue = asn1.result; // Should be just a simple INTEGER
					break;
				case "2.5.29.21":
					// CRLReason
					this.parsedValue = asn1.result; // Should be just a simple ENUMERATED
					break;
				case "2.5.29.24":
					// InvalidityDate
					this.parsedValue = asn1.result; // Should be just a simple GeneralizedTime
					break;
				case "2.5.29.28":
					// IssuingDistributionPoint
					this.parsedValue = new _IssuingDistributionPoint2.default({ schema: asn1.result });
					break;
				case "2.5.29.29":
					// CertificateIssuer
					this.parsedValue = new _GeneralNames2.default({ schema: asn1.result }); // Should be just a simple
					break;
				case "2.5.29.30":
					// NameConstraints
					this.parsedValue = new _NameConstraints2.default({ schema: asn1.result });
					break;
				case "2.5.29.31": // CRLDistributionPoints
				case "2.5.29.46":
					// FreshestCRL
					this.parsedValue = new _CRLDistributionPoints2.default({ schema: asn1.result });
					break;
				case "2.5.29.32":
					// CertificatePolicies
					this.parsedValue = new _CertificatePolicies2.default({ schema: asn1.result });
					break;
				case "2.5.29.33":
					// PolicyMappings
					this.parsedValue = new _PolicyMappings2.default({ schema: asn1.result });
					break;
				case "2.5.29.35":
					// AuthorityKeyIdentifier
					this.parsedValue = new _AuthorityKeyIdentifier2.default({ schema: asn1.result });
					break;
				case "2.5.29.36":
					// PolicyConstraints
					this.parsedValue = new _PolicyConstraints2.default({ schema: asn1.result });
					break;
				case "2.5.29.37":
					// ExtKeyUsage
					this.parsedValue = new _ExtKeyUsage2.default({ schema: asn1.result });
					break;
				case "2.5.29.54":
					// InhibitAnyPolicy
					this.parsedValue = asn1.result; // Should be just a simple INTEGER
					break;
				case "1.3.6.1.5.5.7.1.1": // AuthorityInfoAccess
				case "1.3.6.1.5.5.7.1.11":
					// SubjectInfoAccess
					this.parsedValue = new _InfoAccess2.default({ schema: asn1.result });
					break;
				default:
			}
			//endregion
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
			//region Create array for output sequence
			var outputArray = [];

			outputArray.push(new asn1js.ObjectIdentifier({ value: this.extnID }));

			if (this.critical !== Extension.defaultValues("critical")) outputArray.push(new asn1js.Boolean({ value: this.critical }));

			outputArray.push(this.extnValue);
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
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
				extnID: this.extnID,
				extnValue: this.extnValue.toJSON()
			};

			if (this.critical !== Extension.defaultValues("critical")) object.critical = this.critical;

			if ("parsedValue" in this) object.parsedValue = this.parsedValue.toJSON();

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "extnID":
					return "";
				case "critical":
					return false;
				case "extnValue":
					return new asn1js.OctetString();
				case "parsedValue":
					return {};
				default:
					throw new Error("Invalid member name for Extension class: " + memberName);
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

			//Extension  ::=  SEQUENCE  {
			//    extnID      OBJECT IDENTIFIER,
			//    critical    BOOLEAN DEFAULT FALSE,
			//    extnValue   OCTET STRING
			//}

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [extnID]
    * @property {string} [critical]
    * @property {string} [extnValue]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.extnID || "" }), new asn1js.Boolean({
					name: names.critical || "",
					optional: true
				}), new asn1js.OctetString({ name: names.extnValue || "" })]
			});
		}
	}]);

	return Extension;
}();
//**************************************************************************************


exports.default = Extension;
//# sourceMappingURL=Extension.js.map