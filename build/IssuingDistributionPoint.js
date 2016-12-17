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

var IssuingDistributionPoint = function () {
	//**********************************************************************************
	/**
  * Constructor for IssuingDistributionPoint class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function IssuingDistributionPoint() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, IssuingDistributionPoint);

		//region Internal properties of the object
		if ("distributionPoint" in parameters)
			/**
    * @type {Array.<GeneralName>|RelativeDistinguishedNames}
    * @description distributionPoint
    */
			this.distributionPoint = (0, _pvutils.getParametersValue)(parameters, "distributionPoint", IssuingDistributionPoint.defaultValues("distributionPoint"));

		/**
   * @type {boolean}
   * @description onlyContainsUserCerts
   */
		this.onlyContainsUserCerts = (0, _pvutils.getParametersValue)(parameters, "onlyContainsUserCerts", IssuingDistributionPoint.defaultValues("onlyContainsUserCerts"));

		/**
   * @type {boolean}
   * @description onlyContainsCACerts
   */
		this.onlyContainsCACerts = (0, _pvutils.getParametersValue)(parameters, "onlyContainsCACerts", IssuingDistributionPoint.defaultValues("onlyContainsCACerts"));

		if ("onlySomeReasons" in parameters)
			/**
    * @type {number}
    * @description onlySomeReasons
    */
			this.onlySomeReasons = (0, _pvutils.getParametersValue)(parameters, "onlySomeReasons", IssuingDistributionPoint.defaultValues("onlySomeReasons"));

		/**
   * @type {boolean}
   * @description indirectCRL
   */
		this.indirectCRL = (0, _pvutils.getParametersValue)(parameters, "indirectCRL", IssuingDistributionPoint.defaultValues("indirectCRL"));

		/**
   * @type {boolean}
   * @description onlyContainsAttributeCerts
   */
		this.onlyContainsAttributeCerts = (0, _pvutils.getParametersValue)(parameters, "onlyContainsAttributeCerts", IssuingDistributionPoint.defaultValues("onlyContainsAttributeCerts"));
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


	_createClass(IssuingDistributionPoint, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, IssuingDistributionPoint.schema({
				names: {
					distributionPoint: "distributionPoint",
					distributionPointNames: "distributionPointNames",
					onlyContainsUserCerts: "onlyContainsUserCerts",
					onlyContainsCACerts: "onlyContainsCACerts",
					onlySomeReasons: "onlySomeReasons",
					indirectCRL: "indirectCRL",
					onlyContainsAttributeCerts: "onlyContainsAttributeCerts"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for IssuingDistributionPoint");
			//endregion

			//region Get internal properties from parsed schema
			if ("distributionPoint" in asn1.result) {
				switch (true) {
					case asn1.result.distributionPoint.idBlock.tagNumber === 0:
						// GENERAL_NAMES variant
						this.distributionPoint = Array.from(asn1.result.distributionPointNames, function (element) {
							return new _GeneralName2.default({ schema: element });
						});
						break;
					case asn1.result.distributionPoint.idBlock.tagNumber === 1:
						// RDN variant
						{
							asn1.result.distributionPoint.idBlock.tagClass = 1; // UNIVERSAL
							asn1.result.distributionPoint.idBlock.tagNumber = 16; // SEQUENCE

							this.distributionPoint = new _RelativeDistinguishedNames2.default({ schema: asn1.result.distributionPoint });
						}
						break;
					default:
						throw new Error("Unknown tagNumber for distributionPoint: {$asn1.result.distributionPoint.idBlock.tagNumber}");
				}
			}

			if ("onlyContainsUserCerts" in asn1.result) {
				var view = new Uint8Array(asn1.result.onlyContainsUserCerts.valueBlock.valueHex);
				this.onlyContainsUserCerts = view[0] !== 0x00;
			}

			if ("onlyContainsCACerts" in asn1.result) {
				var _view = new Uint8Array(asn1.result.onlyContainsCACerts.valueBlock.valueHex);
				this.onlyContainsCACerts = _view[0] !== 0x00;
			}

			if ("onlySomeReasons" in asn1.result) {
				var _view2 = new Uint8Array(asn1.result.onlySomeReasons.valueBlock.valueHex);
				this.onlySomeReasons = _view2[0];
			}

			if ("indirectCRL" in asn1.result) {
				var _view3 = new Uint8Array(asn1.result.indirectCRL.valueBlock.valueHex);
				this.indirectCRL = _view3[0] !== 0x00;
			}

			if ("onlyContainsAttributeCerts" in asn1.result) {
				var _view4 = new Uint8Array(asn1.result.onlyContainsAttributeCerts.valueBlock.valueHex);
				this.onlyContainsAttributeCerts = _view4[0] !== 0x00;
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
			//region Create array for output sequence
			var outputArray = [];

			if ("distributionPoint" in this) {
				var value = void 0;

				if (this.distributionPoint instanceof Array) {
					value = new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: Array.from(this.distributionPoint, function (element) {
							return element.toSchema();
						})
					});
				} else {
					value = this.distributionPoint.toSchema();

					value.idBlock.tagClass = 3; // CONTEXT - SPECIFIC
					value.idBlock.tagNumber = 1; // [1]
				}

				outputArray.push(value);
			}

			if (this.onlyContainsUserCerts !== IssuingDistributionPoint.defaultValues("onlyContainsUserCerts")) {
				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					valueHex: new Uint8Array([0xFF]).buffer
				}));
			}

			if (this.onlyContainsCACerts !== IssuingDistributionPoint.defaultValues("onlyContainsCACerts")) {
				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					},
					valueHex: new Uint8Array([0xFF]).buffer
				}));
			}

			if ("onlySomeReasons" in this) {
				var buffer = new ArrayBuffer(1);
				var view = new Uint8Array(buffer);

				view[0] = this.onlySomeReasons;

				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					valueHex: buffer
				}));
			}

			if (this.indirectCRL !== IssuingDistributionPoint.defaultValues("indirectCRL")) {
				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4 // [4]
					},
					valueHex: new Uint8Array([0xFF]).buffer
				}));
			}

			if (this.onlyContainsAttributeCerts !== IssuingDistributionPoint.defaultValues("onlyContainsAttributeCerts")) {
				outputArray.push(new asn1js.Primitive({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 5 // [5]
					},
					valueHex: new Uint8Array([0xFF]).buffer
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

			if (this.onlyContainsUserCerts !== IssuingDistributionPoint.defaultValues("onlyContainsUserCerts")) object.onlyContainsUserCerts = this.onlyContainsUserCerts;

			if (this.onlyContainsCACerts !== IssuingDistributionPoint.defaultValues("onlyContainsCACerts")) object.onlyContainsCACerts = this.onlyContainsCACerts;

			if ("onlySomeReasons" in this) object.onlySomeReasons = this.onlySomeReasons;

			if (this.indirectCRL !== IssuingDistributionPoint.defaultValues("indirectCRL")) object.indirectCRL = this.indirectCRL;

			if (this.onlyContainsAttributeCerts !== IssuingDistributionPoint.defaultValues("onlyContainsAttributeCerts")) object.onlyContainsAttributeCerts = this.onlyContainsAttributeCerts;

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "distributionPoint":
					return [];
				case "onlyContainsUserCerts":
					return false;
				case "onlyContainsCACerts":
					return false;
				case "onlySomeReasons":
					return 0;
				case "indirectCRL":
					return false;
				case "onlyContainsAttributeCerts":
					return false;
				default:
					throw new Error("Invalid member name for IssuingDistributionPoint class: " + memberName);
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

			// IssuingDistributionPoint OID ::= 2.5.29.28
			//
			//IssuingDistributionPoint ::= SEQUENCE {
			//    distributionPoint          [0] DistributionPointName OPTIONAL,
			//    onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
			//    onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
			//    onlySomeReasons            [3] ReasonFlags OPTIONAL,
			//    indirectCRL                [4] BOOLEAN DEFAULT FALSE,
			//    onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
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
    * @property {string} [onlyContainsUserCerts]
    * @property {string} [onlyContainsCACerts]
    * @property {string} [onlySomeReasons]
    * @property {string} [indirectCRL]
    * @property {string} [onlyContainsAttributeCerts]
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
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: _RelativeDistinguishedNames2.default.schema().valueBlock.value
						})]
					})]
				}), new asn1js.Primitive({
					name: names.onlyContainsUserCerts || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}), // IMPLICIT boolean value
				new asn1js.Primitive({
					name: names.onlyContainsCACerts || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				}), // IMPLICIT boolean value
				new asn1js.Primitive({
					name: names.onlySomeReasons || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					}
				}), // IMPLICIT bitstring value
				new asn1js.Primitive({
					name: names.indirectCRL || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4 // [4]
					}
				}), // IMPLICIT boolean value
				new asn1js.Primitive({
					name: names.onlyContainsAttributeCerts || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 5 // [5]
					}
				}) // IMPLICIT boolean value
				]
			});
		}
	}]);

	return IssuingDistributionPoint;
}();
//**************************************************************************************


exports.default = IssuingDistributionPoint;
//# sourceMappingURL=IssuingDistributionPoint.js.map