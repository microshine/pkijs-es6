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

var CertificateSet = function () {
	//**********************************************************************************
	/**
  * Constructor for CertificateSet class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertificateSet() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertificateSet);

		//region Internal properties of the object
		/**
   * @type {Array}
   * @description certificates
   */
		this.certificates = (0, _pvutils.getParametersValue)(parameters, "certificates", CertificateSet.defaultValues("certificates"));
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


	_createClass(CertificateSet, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CertificateSet.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CMS_CERTIFICATE_SET");
			//endregion

			//region Get internal properties from parsed schema
			this.certificates = Array.from(asn1.result.certificates, function (element) {
				if (element.idBlock.tagClass === 1) return new _Certificate2.default({ schema: element });

				return element;
			});
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
			return new asn1js.Set({
				value: Array.from(this.certificates, function (element) {
					if (element instanceof _Certificate2.default) return element.toSchema();

					return element;
				})
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
				certificates: Array.from(this.certificates, function (element) {
					return element.toJSON();
				})
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "certificates":
					return [];
				default:
					throw new Error("Invalid member name for Attribute class: " + memberName);
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

			//CertificateSet ::= SET OF CertificateChoices
			//
			//CertificateChoices ::= CHOICE {
			//    certificate Certificate,
			//    extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
			//    v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
			//    v2AttrCert [2] IMPLICIT AttributeCertificateV2,
			//    other [3] IMPLICIT OtherCertificateFormat }

			/**
    * @type {Object}
    * @property {string} [blockName]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Set({
				name: names.blockName || "",
				value: [new asn1js.Repeated({
					name: names.certificates || "",
					value: new asn1js.Choice({
						value: [_Certificate2.default.schema(), new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: [new asn1js.Any()]
						}), // JUST A STUB
						new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 2 // [2]
							},
							value: [new asn1js.Any()]
						}), // JUST A STUB
						new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 3 // [3]
							},
							value: [new asn1js.ObjectIdentifier(), new asn1js.Any()]
						})]
					})
				})]
			}); // TODO: add definition for "AttributeCertificateV2"
		}
	}]);

	return CertificateSet;
}();
//**************************************************************************************


exports.default = CertificateSet;
//# sourceMappingURL=CertificateSet.js.map