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

var EncapsulatedContentInfo = function () {
	//**********************************************************************************
	/**
  * Constructor for EncapsulatedContentInfo class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function EncapsulatedContentInfo() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, EncapsulatedContentInfo);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description eContentType
   */
		this.eContentType = (0, _pvutils.getParametersValue)(parameters, "eContentType", EncapsulatedContentInfo.defaultValues("eContentType"));

		if ("eContent" in parameters) {
			/**
    * @type {OctetString}
    * @description eContent
    */
			this.eContent = (0, _pvutils.getParametersValue)(parameters, "eContent", EncapsulatedContentInfo.defaultValues("eContent"));
			if (this.eContent.idBlock.tagClass === 1 && this.eContent.idBlock.tagNumber === 4) {
				// #region Divide OCTETSTRING value down to small pieces
				if (this.eContent.idBlock.isConstructed === false) {
					var constrString = new asn1js.OctetString({
						idBlock: { isConstructed: true },
						isConstructed: true
					});

					var offset = 0;
					var length = this.eContent.valueBlock.valueHex.byteLength;

					while (length > 0) {
						var pieceView = new Uint8Array(this.eContent.valueBlock.valueHex, offset, offset + 65536 > this.eContent.valueBlock.valueHex.byteLength ? this.eContent.valueBlock.valueHex.byteLength - offset : 65536);
						var _array = new ArrayBuffer(pieceView.length);
						var _view = new Uint8Array(_array);

						for (var i = 0; i < _view.length; i++) {
							_view[i] = pieceView[i];
						}constrString.valueBlock.value.push(new asn1js.OctetString({ valueHex: _array }));

						length -= pieceView.length;
						offset += pieceView.length;
					}

					this.eContent = constrString;
				}
				// #endregion
			}
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


	_createClass(EncapsulatedContentInfo, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, EncapsulatedContentInfo.schema({
				names: {
					eContentType: "eContentType",
					eContent: "eContent"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for EncapsulatedContentInfo");
			//endregion

			//region Get internal properties from parsed schema
			this.eContentType = asn1.result.eContentType.valueBlock.toString();
			if ("eContent" in asn1.result) this.eContent = asn1.result.eContent;
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

			outputArray.push(new asn1js.ObjectIdentifier({ value: this.eContentType }));
			if ("eContent" in this) {
				if (EncapsulatedContentInfo.compareWithDefault("eContent", this.eContent) === false) {
					outputArray.push(new asn1js.Constructed({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [this.eContent]
					}));
				}
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
			var _object = {
				eContentType: this.eContentType
			};

			if ("eContent" in this) {
				if (EncapsulatedContentInfo.compareWithDefault("eContent", this.eContent) === false) _object.eContent = this.eContent.toJSON();
			}

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "eContentType":
					return "";
				case "eContent":
					return new asn1js.OctetString();
				default:
					throw new Error("Invalid member name for EncapsulatedContentInfo class: " + memberName);
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
				case "eContentType":
					return memberValue === "";
				case "eContent":
					return memberValue.isEqual(EncapsulatedContentInfo.defaultValues("eContent"));
				default:
					throw new Error("Invalid member name for EncapsulatedContentInfo class: " + memberName);
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

			//EncapsulatedContentInfo ::= SEQUENCE {
			//    eContentType ContentType,
			//    eContent [0] EXPLICIT OCTET STRING OPTIONAL } // Changed it to ANY, as in PKCS#7

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [type]
    * @property {string} [setName]
    * @property {string} [values]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.eContentType || "" }), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					value: [new asn1js.Any({ name: names.eContent || "" }) // In order to aling this with PKCS#7 and CMS as well
					]
				})]
			});
		}
	}]);

	return EncapsulatedContentInfo;
}();
//**************************************************************************************


exports.default = EncapsulatedContentInfo;
//# sourceMappingURL=EncapsulatedContentInfo.js.map