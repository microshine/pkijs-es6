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

var PolicyMapping = function () {
	//**********************************************************************************
	/**
  * Constructor for PolicyMapping class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PolicyMapping() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PolicyMapping);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description issuerDomainPolicy
   */
		this.issuerDomainPolicy = (0, _pvutils.getParametersValue)(parameters, "issuerDomainPolicy", PolicyMapping.defaultValues("issuerDomainPolicy"));
		/**
   * @type {string}
   * @description subjectDomainPolicy
   */
		this.subjectDomainPolicy = (0, _pvutils.getParametersValue)(parameters, "subjectDomainPolicy", PolicyMapping.defaultValues("subjectDomainPolicy"));
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


	_createClass(PolicyMapping, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PolicyMapping.schema({
				names: {
					issuerDomainPolicy: "issuerDomainPolicy",
					subjectDomainPolicy: "subjectDomainPolicy"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PolicyMapping");
			//endregion

			//region Get internal properties from parsed schema
			this.issuerDomainPolicy = asn1.result.issuerDomainPolicy.valueBlock.toString();
			this.subjectDomainPolicy = asn1.result.subjectDomainPolicy.valueBlock.toString();
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
				value: [new asn1js.ObjectIdentifier({ value: this.issuerDomainPolicy }), new asn1js.ObjectIdentifier({ value: this.subjectDomainPolicy })]
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
				issuerDomainPolicy: this.issuerDomainPolicy,
				subjectDomainPolicy: this.subjectDomainPolicy
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "issuerDomainPolicy":
					return "";
				case "subjectDomainPolicy":
					return "";
				default:
					throw new Error("Invalid member name for PolicyMapping class: " + memberName);
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

			//PolicyMapping ::= SEQUENCE {
			//    issuerDomainPolicy      CertPolicyId,
			//    subjectDomainPolicy     CertPolicyId }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [issuerDomainPolicy]
    * @property {string} [subjectDomainPolicy]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.issuerDomainPolicy || "" }), new asn1js.ObjectIdentifier({ name: names.subjectDomainPolicy || "" })]
			});
		}
	}]);

	return PolicyMapping;
}();
//**************************************************************************************


exports.default = PolicyMapping;
//# sourceMappingURL=PolicyMapping.js.map