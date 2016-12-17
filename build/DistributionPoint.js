"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _GeneralName = require("./GeneralName");

var _GeneralName2 = _interopRequireDefault(_GeneralName);

var _RelativeDistinguishedNames = require("./RelativeDistinguishedNames");

var _RelativeDistinguishedNames2 = _interopRequireDefault(_RelativeDistinguishedNames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var DistributionPoint = function () {
	//**********************************************************************************
	/**
  * Constructor for DistributionPoint class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  * @property {Object} [distributionPoint]
  * @property {Object} [reasons]
  * @property {Object} [cRLIssuer]
  */

	function DistributionPoint() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, DistributionPoint);

		//region Internal properties of the object
		if ("distributionPoint" in parameters)
			/**
    * @type {Array.<GeneralName>}
    * @description distributionPoint
    */
			this.distributionPoint = (0, _pvutils.getParametersValue)(parameters, "distributionPoint", DistributionPoint.defaultValues("distributionPoint"));

		if ("reasons" in parameters)
			/**
    * @type {BitString}
    * @description values
    */
			this.reasons = (0, _pvutils.getParametersValue)(parameters, "reasons", DistributionPoint.defaultValues("reasons"));

		if ("cRLIssuer" in parameters)
			/**
    * @type {Array.<GeneralName>}
    * @description cRLIssuer
    */
			this.cRLIssuer = (0, _pvutils.getParametersValue)(parameters, "cRLIssuer", DistributionPoint.defaultValues("cRLIssuer"));
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


	_createClass(DistributionPoint, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, DistributionPoint.schema({
				names: {
					distributionPoint: "distributionPoint",
					distributionPointNames: "distributionPointNames",
					reasons: "reasons",
					cRLIssuer: "cRLIssuer",
					cRLIssuerNames: "cRLIssuerNames"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for DistributionPoint");
			//endregion

			//region Get internal properties from parsed schema
			if ("distributionPoint" in asn1.result) {
				if (asn1.result.distributionPoint.idBlock.tagNumber === 0) // GENERAL_NAMES variant
					this.distributionPoint = Array.from(asn1.result.distributionPointNames, function (element) {
						return new _GeneralName2.default({ schema: element });
					});

				if (asn1.result.distributionPoint.idBlock.tagNumber === 1) // RDN variant
					{
						asn1.result.distributionPoint.idBlock.tagClass = 1; // UNIVERSAL
						asn1.result.distributionPoint.idBlock.tagNumber = 16; // SEQUENCE

						this.distributionPoint = new _RelativeDistinguishedNames2.default({ schema: asn1.result.distributionPoint });
					}
			}

			if ("reasons" in asn1.result) this.reasons = new asn1js.BitString({ valueHex: asn1.result.reasons.valueBlock.valueHex });

			if ("cRLIssuer" in asn1.result) this.cRLIssuer = Array.from(asn1.result.cRLIssuerNames, function (element) {
				return new _GeneralName2.default({ schema: element });
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
			//region Create array for output sequence
			var outputArray = [];

			if ("distributionPoint" in this) {
				var internalValue = void 0;

				if (this.distributionPoint instanceof Array) {
					internalValue = new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: Array.from(this.distributionPoint, function (element) {
							return element.toSchema();
						})
					});
				} else {
					internalValue = new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 1 // [1]
						},
						value: [this.distributionPoint.toSchema()]
					});
				}

				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [internalValue]
				}));
			}

			if ("reasons" in this) {
				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					valueHex: this.reasons.valueBlock.valueHex
				}));
			}

			if ("cRLIssuer" in this) {
				outputArray.push(new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					value: Array.from(this.cRLIssuer, function (element) {
						return element.toSchema();
					})
				}));
			}
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
			var object = {};

			if ("distributionPoint" in this) {
				if (this.distributionPoint instanceof Array) object.distributionPoint = Array.from(this.distributionPoint, function (element) {
					return element.toJSON();
				});else object.distributionPoint = this.distributionPoint.toJSON();
			}

			if ("reasons" in this) object.reasons = this.reasons.toJSON();

			if ("cRLIssuer" in this) object.cRLIssuer = Array.from(this.cRLIssuer, function (element) {
				return element.toJSON();
			});

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "distributionPoint":
					return [];
				case "reasons":
					return new asn1js.BitString();
				case "cRLIssuer":
					return [];
				default:
					throw new Error("Invalid member name for DistributionPoint class: " + memberName);
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

			//DistributionPoint ::= SEQUENCE {
			//    distributionPoint       [0]     DistributionPointName OPTIONAL,
			//    reasons                 [1]     ReasonFlags OPTIONAL,
			//    cRLIssuer               [2]     GeneralNames OPTIONAL }
			//
			//DistributionPointName ::= CHOICE {
			//    fullName                [0]     GeneralNames,
			//    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
			//
			//ReasonFlags ::= BIT STRING {
			//    unused                  (0),
			//    keyCompromise           (1),
			//    cACompromise            (2),
			//    affiliationChanged      (3),
			//    superseded              (4),
			//    cessationOfOperation    (5),
			//    certificateHold         (6),
			//    privilegeWithdrawn      (7),
			//    aACompromise            (8) }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [distributionPoint]
    * @property {string} [distributionPointNames]
    * @property {string} [reasons]
    * @property {string} [cRLIssuer]
    * @property {string} [cRLIssuerNames]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Choice({
						value: [new asn1js.Constructed({
							name: names.distributionPoint || "",
							optional: true,
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 0 // [0]
							},
							value: [new asn1js.Repeated({
								name: names.distributionPointNames || "",
								value: _GeneralName2.default.schema()
							})]
						}), new asn1js.Constructed({
							name: names.distributionPoint || "",
							optional: true,
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: _RelativeDistinguishedNames2.default.schema().valueBlock.value
						})]
					})]
				}), new asn1js.Primitive({
					name: names.reasons || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}), // IMPLICIT bitstring value
				new asn1js.Constructed({
					name: names.cRLIssuer || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					value: [new asn1js.Repeated({
						name: names.cRLIssuerNames || "",
						value: _GeneralName2.default.schema()
					})]
				}) // IMPLICIT bitstring value
				]
			});
		}
	}]);

	return DistributionPoint;
}();
//**************************************************************************************


exports.default = DistributionPoint;
//# sourceMappingURL=DistributionPoint.js.map